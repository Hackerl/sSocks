#include "common.h"
#include <asyncio/signal.h>
#include <asyncio/net/tls.h>
#include <asyncio/net/dgram.h>
#include <asyncio/net/stream.h>
#include <zero/log.h>
#include <zero/cmdline.h>
#include <zero/formatter.h>

struct User {
    std::string username;
    std::string password;
};

template<>
User zero::scan(const std::string_view input) {
    const auto tokens = strings::split(input, ":");

    if (tokens.size() != 2)
        throw std::runtime_error{fmt::format("Invalid user format '{}', expected 'username:password'", input)};

    return User{strings::trim(tokens[0]), strings::trim(tokens[1])};
}

bool matchSource(const Target &source, const asyncio::net::Address &from) {
    return std::visit(
        [&]<typename T>(const T &arg) {
            if constexpr (std::is_same_v<T, HostAddress>) {
                return true;
            }
            else if constexpr (std::is_same_v<T, asyncio::net::IPv4Address>) {
                if (!std::holds_alternative<asyncio::net::IPv4Address>(from))
                    return false;

                const auto [sourceIP, sourcePort] = arg;
                const auto [fromIP, fromPort] = std::get<asyncio::net::IPv4Address>(from);

                if (sourcePort != 0 && sourcePort != fromPort)
                    return false;

                if (sourceIP == asyncio::net::UnspecifiedIPv4)
                    return true;

                return sourceIP == fromIP;
            }
            else {
                if (!std::holds_alternative<asyncio::net::IPv6Address>(from))
                    return false;

                const auto &[sourceIP, sourcePort, sourceZone] = arg;
                const auto &[fromIP, fromPort, fromZone] = std::get<asyncio::net::IPv6Address>(from);

                if (sourcePort != 0 && sourcePort != fromPort)
                    return false;

                if (sourceIP == asyncio::net::UnspecifiedIPv6)
                    return true;

                return sourceIP == fromIP;
            }
        },
        source
    );
}

asyncio::task::Task<std::tuple<int, Target>> readRequest(asyncio::IReader &reader) {
    std::array<std::byte, 4> header{};
    co_await asyncio::error::guard(reader.readExactly(header));

    if (std::to_integer<int>(header[0]) != 5)
        throw std::runtime_error{
            fmt::format("Mismatched SOCKS5 version: expected 5, got {}", std::to_integer<int>(header[0]))
        };

    const auto command = std::to_integer<int>(header[1]);

    switch (std::to_integer<int>(header[3])) {
    case 1: {
        std::array<std::byte, 4> ip{};
        co_await asyncio::error::guard(reader.readExactly(ip));

        const auto port = co_await asyncio::error::guard(asyncio::binary::readBE<std::uint16_t>(reader));
        co_return std::tuple<int, Target>{command, asyncio::net::IPv4Address{ip, port}};
    }

    case 3: {
        std::byte length{};
        co_await asyncio::error::guard(reader.readExactly({&length, 1}));

        std::string host;
        host.resize(std::to_integer<std::size_t>(length));

        co_await asyncio::error::guard(reader.readExactly(std::as_writable_bytes(std::span{host})));

        const auto port = co_await asyncio::error::guard(asyncio::binary::readBE<std::uint16_t>(reader));
        co_return std::tuple<int, Target>{command, HostAddress{port, std::move(host)}};
    }

    case 4: {
        std::array<std::byte, 16> ip{};
        co_await asyncio::error::guard(reader.readExactly(ip));

        const auto port = co_await asyncio::error::guard(asyncio::binary::readBE<std::uint16_t>(reader));
        co_return std::tuple<int, Target>{command, asyncio::net::IPv6Address{ip, port}};
    }

    default:
        throw std::runtime_error{fmt::format("Unsupported SOCKS5 address type: {}", std::to_integer<int>(header[3]))};
    }
}

asyncio::task::Task<User> readUser(asyncio::IReader &reader) {
    std::byte version{};
    co_await asyncio::error::guard(reader.readExactly({&version, 1}));

    if (std::to_integer<int>(version) != 1)
        throw std::runtime_error{
            fmt::format("Mismatched authentication version: expected 1, got {}", std::to_integer<int>(version))
        };

    std::byte length{};
    co_await asyncio::error::guard(reader.readExactly({&length, 1}));

    std::string username;
    username.resize(std::to_integer<std::size_t>(length));

    co_await asyncio::error::guard(reader.readExactly(std::as_writable_bytes(std::span{username})));
    co_await asyncio::error::guard(reader.readExactly({&length, 1}));

    std::string password;
    password.resize(std::to_integer<std::size_t>(length));

    co_await asyncio::error::guard(reader.readExactly(std::as_writable_bytes(std::span{password})));

    co_return User{std::move(username), std::move(password)};
}

asyncio::task::Task<void>
handshake(asyncio::net::TCPStream &stream, const std::optional<User> user) {
    std::array<std::byte, 2> header{};
    co_await asyncio::error::guard(stream.readExactly(header));

    std::vector<std::byte> methods(std::to_integer<std::size_t>(header[1]));
    co_await asyncio::error::guard(stream.readExactly(methods));

    if (!user) {
        constexpr std::array response{std::byte{5}, std::byte{0}};
        co_await asyncio::error::guard(stream.writeAll(response));
        co_return;
    }

    if (std::ranges::find(methods, std::byte{2}) == methods.end()) {
        constexpr std::array response{std::byte{5}, std::byte{0xff}};
        co_await asyncio::error::guard(stream.writeAll(response));
        throw std::runtime_error{"Unsupported authentication method"};
    }

    constexpr std::array response{std::byte{5}, std::byte{2}};
    co_await asyncio::error::guard(stream.writeAll(response));

    const auto [username, password] = co_await readUser(stream);
    Z_LOG_INFO("Authenticating user: {}", username);

    if (username != user->username || password != user->password) {
        constexpr std::array result{std::byte{1}, std::byte{1}};
        co_await asyncio::error::guard(stream.writeAll(result));
        throw std::runtime_error{fmt::format("Authentication failed for user '{}'", username)};
    }

    constexpr std::array result{std::byte{1}, std::byte{0}};
    co_await asyncio::error::guard(stream.writeAll(result));
}

std::tuple<Target, std::span<const std::byte>> unpack(const std::span<const std::byte> data) {
    if (data.size() < 4)
        throw std::runtime_error{"UDP packet too short"};

    if (data[2] != std::byte{0})
        throw std::runtime_error{"UDP fragmentation not supported"};

    switch (std::to_integer<int>(data[3])) {
    case 1: {
        if (data.size() < 10)
            throw std::runtime_error{"UDP packet too short for IPv4 address"};

        asyncio::net::IPv4Address address{};

        address.port = ntohs(*reinterpret_cast<const std::uint16_t *>(data.data() + 8));
        std::ranges::copy(data.subspan(4, 4), address.ip.begin());

        return {address, data.subspan(10)};
    }

    case 3: {
        if (data.size() < 5)
            throw std::runtime_error{"UDP packet too short for hostname length"};

        const auto length = std::to_integer<std::size_t>(data[4]);

        if (data.size() < 7 + length)
            throw std::runtime_error{"UDP packet too short for hostname address"};

        return {
            HostAddress{
                ntohs(*reinterpret_cast<const std::uint16_t *>(data.data() + 5 + length)),
                {reinterpret_cast<const char *>(data.data()) + 5, length}
            },
            data.subspan(7 + length)
        };
    }

    case 4: {
        if (data.size() < 22)
            throw std::runtime_error{"UDP packet too short for IPv6 address"};

        asyncio::net::IPv6Address address{};

        address.port = ntohs(*reinterpret_cast<const std::uint16_t *>(data.data() + 20));
        std::ranges::copy(data.subspan(4, 16), address.ip.begin());

        return {address, data.subspan(22)};
    }

    default:
        throw std::runtime_error{fmt::format("Unsupported UDP address type: {}", std::to_integer<int>(data[3]))};
    }
}

asyncio::task::Task<asyncio::net::Address>
setupUDP(
    const std::uint64_t id,
    asyncio::net::UDPSocket &local,
    asyncio::net::tls::TLS<asyncio::net::TCPStream> &remote,
    const Target source
) {
    std::array<std::byte, 65535> data; // NOLINT(*-pro-type-member-init)
    const auto &[n, from] = co_await asyncio::error::guard(local.readFrom(data));

    if (!matchSource(source, from))
        throw std::runtime_error{fmt::format("Unexpected source address: {}", from)};

    const auto [target, payload] = unpack({data.data(), n});

    Z_LOG_INFO("[{}] UDP client->remote: {} bytes to {}", id, payload.size(), target);

    co_await writeTarget(remote, target);
    co_await asyncio::error::guard(asyncio::binary::writeBE(remote, static_cast<std::uint32_t>(payload.size())));
    co_await asyncio::error::guard(remote.writeAll(payload));

    co_return from;
}

asyncio::task::Task<void>
UDPToRemote(
    const std::uint64_t id,
    asyncio::net::UDPSocket &local,
    asyncio::IWriter &writer,
    const asyncio::net::Address client
) {
    while (true) {
        std::array<std::byte, 65535> data; // NOLINT(*-pro-type-member-init)

        const auto &[n, from] = co_await asyncio::error::guard(local.readFrom(data));

        if (from != client)
            throw std::runtime_error{fmt::format("Unexpected source address: got {}, expected {}", from, client)};

        const auto [target, payload] = unpack({data.data(), n});

        Z_LOG_DEBUG("[{}] UDP client->remote: {} bytes to {}", id, payload.size(), target);

        co_await writeTarget(writer, target);
        co_await asyncio::error::guard(asyncio::binary::writeBE(writer, static_cast<std::uint32_t>(payload.size())));
        co_await asyncio::error::guard(writer.writeAll(payload));
    }
}

asyncio::task::Task<void>
UDPToClient(
    const std::uint64_t id,
    asyncio::IReader &reader,
    asyncio::net::UDPSocket &local,
    const asyncio::net::Address client
) {
    while (true) {
        const auto target = co_await readTarget(reader);

        if (!target)
            throw std::runtime_error{"Server closed connection during UDP relay"};

        const auto length = co_await asyncio::error::guard(asyncio::binary::readBE<std::uint32_t>(reader));

        Z_LOG_DEBUG("[{}] UDP remote->client: {} bytes from {}", id, length, *target);

        std::vector<std::byte> payload(length);
        co_await asyncio::error::guard(reader.readExactly(payload));

        std::vector response{
            std::byte{0}, std::byte{0},
            std::byte{0}
        };

        if (std::holds_alternative<asyncio::net::IPv4Address>(*target)) {
            response.push_back(std::byte{1});

            const auto [ip, port] = std::get<asyncio::net::IPv4Address>(*target);
            const auto p = htons(port);

            response.append_range(ip);
            response.append_range(std::span{reinterpret_cast<const std::byte *>(&p), sizeof(std::uint16_t)});
            response.append_range(payload);

            co_await asyncio::error::guard(local.writeTo(response, client));
            continue;
        }

        response.push_back(std::byte{4});

        const auto &[ip, port, zone] = std::get<asyncio::net::IPv6Address>(*target);
        const auto p = htons(port);

        response.append_range(ip);
        response.append_range(std::span{reinterpret_cast<const std::byte *>(&p), sizeof(std::uint16_t)});
        response.append_range(payload);

        co_await asyncio::error::guard(local.writeTo(response, client));
    }
}

asyncio::task::Task<void>
proxyUDP(
    const std::uint64_t id,
    asyncio::net::TCPStream stream,
    asyncio::net::tls::TLS<asyncio::net::TCPStream> remote,
    Target source
) {
    auto local = co_await asyncio::error::guard(
        std::visit(
            []<typename T>(T arg) -> std::expected<asyncio::net::UDPSocket, std::error_code> {
                if constexpr (!std::is_same_v<T, asyncio::net::UnixAddress>) {
                    arg.port = 0;
                    return asyncio::net::UDPSocket::bind(arg);
                }
                else {
                    std::unreachable();
                }
            },
            co_await asyncio::error::guard(stream.localAddress())
        )
    );

    const auto address = co_await asyncio::error::guard(local.localAddress());
    Z_LOG_INFO("[{}] UDP associate bound to {}", id, address);

    std::vector response{std::byte{5}, std::byte{0}, std::byte{0}};

    if (std::holds_alternative<asyncio::net::IPv4Address>(address)) {
        response.push_back(std::byte{1});

        const auto [ip, port] = std::get<asyncio::net::IPv4Address>(address);
        const auto bindPort = htons(port);

        response.append_range(ip);
        response.append_range(std::span{reinterpret_cast<const std::byte *>(&bindPort), sizeof(std::uint16_t)});
    }
    else {
        response.push_back(std::byte{4});

        const auto &[ip, port, zone] = std::get<asyncio::net::IPv6Address>(address);
        const auto bindPort = htons(port);

        response.append_range(ip);
        response.append_range(std::span{reinterpret_cast<const std::byte *>(&bindPort), sizeof(std::uint16_t)});
    }

    co_await asyncio::error::guard(stream.writeAll(response));
    co_await asyncio::error::guard(asyncio::binary::writeBE(remote, std::to_underlying(ProxyType::UDP)));

    const auto client = co_await setupUDP(id, local, remote, std::move(source));
    Z_LOG_INFO("[{}] UDP client address: {}", id, client);

    co_await race(
        asyncio::task::spawn([&]() -> asyncio::task::Task<void> {
            while (true) {
                std::array<std::byte, 1024> data; // NOLINT(*-pro-type-member-init)

                if (const auto n = co_await asyncio::error::guard(stream.read(data)); n == 0)
                    break;
            }
        }),
        UDPToRemote(id, local, remote, client),
        UDPToClient(id, remote, local, client)
    );

    co_await asyncio::error::guard(remote.close());
}

asyncio::task::Task<void>
proxyTCP(asyncio::net::TCPStream local, asyncio::net::tls::TLS<asyncio::net::TCPStream> remote, Target target) {
    co_await asyncio::error::guard(asyncio::binary::writeBE(remote, std::to_underlying(ProxyType::TCP)));
    co_await writeTarget(remote, std::move(target));

    if (const auto status = co_await asyncio::error::guard(asyncio::binary::readBE<std::int32_t>(remote));
        static_cast<ProxyStatus>(status) != ProxyStatus::SUCCESS) {
        constexpr std::array response{
            std::byte{5},
            std::byte{5},
            std::byte{0},
            std::byte{1},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}
        };

        co_await asyncio::error::guard(local.writeAll(response));
        co_return;
    }

    constexpr std::array response{
        std::byte{5},
        std::byte{0},
        std::byte{0},
        std::byte{1},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}
    };

    co_await asyncio::error::guard(local.writeAll(response));
    co_await asyncio::error::guard(asyncio::net::copyBidirectional(local, remote));
}

template<typename F>
asyncio::task::Task<void>
handle(const std::uint64_t id, asyncio::net::TCPStream stream, std::optional<User> user, const F connect) {
    Z_LOG_INFO(
        "[{}] New session: fd={} local={} peer={}",
        id,
        stream.fd(),
        co_await asyncio::error::guard(stream.localAddress()),
        co_await asyncio::error::guard(stream.remoteAddress())
    );

    co_await handshake(stream, std::move(user));

    auto request = co_await readRequest(stream);
    auto remote = co_await connect();

    switch (auto &[command, target] = request; command) {
    case 1: {
        Z_LOG_INFO("[{}] CONNECT to {}", id, target);
        co_await proxyTCP(std::move(stream), std::move(remote), std::move(target));
        break;
    }

    case 3: {
        Z_LOG_INFO("[{}] UDP ASSOCIATE from {}", id, target);
        co_await proxyUDP(id, std::move(stream), std::move(remote), std::move(target));
        break;
    }

    default:
        throw std::runtime_error{fmt::format("Unsupported SOCKS5 command: {}", command)};
    }
}

template<typename F>
asyncio::task::Task<void> serve(asyncio::net::TCPListener listener, const std::optional<User> user, const F connect) {
    std::expected<void, std::error_code> result;
    asyncio::task::TaskGroup group;

    while (true) {
        auto stream = co_await listener.accept();

        if (!stream) {
            result = std::unexpected{stream.error()};
            break;
        }

        static std::uint64_t counter;
        const auto id = counter++;

        auto task = handle(id, *std::move(stream), user, connect);
        group.add(task);

        task.future().fail([=](const auto &e) {
            Z_LOG_ERROR("[{}] Session error: {}", id, e);
        });
    }

    co_await group;
    co_await asyncio::error::guard(std::move(result));
}

asyncio::task::Task<void> asyncMain(const int argc, char *argv[]) {
    Z_INIT_CONSOLE_LOG(zero::log::Level::Info);

    zero::Cmdline cmdline;

    cmdline.add<std::string>("server", "Remote secure SOCKS5 server hostname or IP address");
    cmdline.add<std::uint16_t>("port", "Remote secure SOCKS5 server port");

    cmdline.add<std::filesystem::path>("ca", "CA certificate file path");
    cmdline.add<std::filesystem::path>("cert", "Client certificate file path");
    cmdline.add<std::filesystem::path>("key", "Private key file path");

    cmdline.addOptional<std::string>("bind-ip", '\0', "Local SOCKS5 server bind IP address", "127.0.0.1");
    cmdline.addOptional<std::uint16_t>("bind-port", '\0', "Local SOCKS5 server bind port", 1080);
    cmdline.addOptional<User>("user", '\0', "SOCKS5 authentication credentials (username:password)");

    cmdline.parse(argc, argv);

    const auto server = cmdline.get<std::string>("server");
    const auto port = cmdline.get<std::uint16_t>("port");
    const auto caFile = cmdline.get<std::filesystem::path>("ca");
    const auto certFile = cmdline.get<std::filesystem::path>("cert");
    const auto keyFile = cmdline.get<std::filesystem::path>("key");

    const auto bindIP = cmdline.getOptional<std::string>("bind-ip");
    const auto bindPort = cmdline.getOptional<std::uint16_t>("bind-port");
    auto user = cmdline.getOptional<User>("user");

    auto ca = co_await asyncio::error::guard(asyncio::net::tls::Certificate::loadFile(caFile));
    auto cert = co_await asyncio::error::guard(asyncio::net::tls::Certificate::loadFile(certFile));
    auto key = co_await asyncio::error::guard(asyncio::net::tls::PrivateKey::loadFile(keyFile));

    auto context = co_await asyncio::error::guard(
        asyncio::net::tls::ClientConfig{}
        .rootCAs({std::move(ca)})
        .certKeyPairs({{std::move(cert), std::move(key)}})
        .build()
    );

    auto listener = co_await asyncio::error::guard(asyncio::net::TCPListener::listen(*bindIP, *bindPort));
    auto signal = asyncio::Signal::make();

    co_await race(
        serve(
            std::move(listener),
            std::move(user),
            [
                =, context = std::move(context)
            ]() -> asyncio::task::Task<asyncio::net::tls::TLS<asyncio::net::TCPStream>> {
                co_return co_await asyncio::error::guard(
                    asyncio::net::tls::connect(
                        co_await asyncio::error::guard(asyncio::net::TCPStream::connect(server, port)),
                        context
                    )
                );
            }
        ),
        asyncio::task::spawn([&]() -> asyncio::task::Task<void> {
            co_await asyncio::error::guard(signal.on(SIGINT));
        })
    );
}
