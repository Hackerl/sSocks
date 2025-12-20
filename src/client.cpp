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

Z_DEFINE_ERROR_CODE_EX(
    ScanUserError,
    "zero::scan<User>",
    INVALID_FORMAT, "Invalid user information", std::errc::invalid_argument
)

Z_DECLARE_ERROR_CODE(ScanUserError)
Z_DEFINE_ERROR_CATEGORY_INSTANCES(ScanUserError)

template<>
std::expected<User, std::error_code> zero::scan(const std::string_view input) {
    const auto tokens = strings::split(input, ":");

    if (tokens.size() != 2)
        return std::unexpected{ScanUserError::INVALID_FORMAT};

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

                if (sourceIP == zero::os::net::UNSPECIFIED_IPV4)
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

                if (sourceIP == zero::os::net::UNSPECIFIED_IPV6)
                    return true;

                return sourceIP == fromIP;
            }
        },
        source
    );
}

Z_DEFINE_ERROR_CODE(
    Socks5Error,
    "socks5",
    MISMATCH_VERSION, "Mismatched SOCKS5 version",
    UNSUPPORTED_COMMAND, "Unsupported SOCKS5 command",
    UNSUPPORTED_ADDRESS_TYPE, "Unsupported address type",
    MISMATCH_AUTHENTICATION_VERSION, "Mismatched authentication version",
    UNSUPPORTED_AUTHENTICATION_METHOD, "Unsupported authentication method",
    AUTHENTICATION_FAILED, "Authentication failed",
    UNEXPECTED_SOURCE_ADDRESS, "Unexpected source address",
    INVALID_UDP_PACKET, "Invalid UDP packet"
)

Z_DECLARE_ERROR_CODE(Socks5Error)
Z_DEFINE_ERROR_CATEGORY_INSTANCES(Socks5Error)

asyncio::task::Task<std::tuple<int, Target>> readRequest(asyncio::IReader &reader) {
    std::array<std::byte, 4> header{};
    zero::error::guard(co_await reader.readExactly(header));

    if (std::to_integer<int>(header[0]) != 5)
        throw zero::error::SystemError{Socks5Error::MISMATCH_VERSION};

    const auto command = std::to_integer<int>(header[1]);

    switch (std::to_integer<int>(header[3])) {
    case 1: {
        std::array<std::byte, 4> ip{};
        zero::error::guard(co_await reader.readExactly(ip));

        const auto port = zero::error::guard(co_await asyncio::binary::readBE<std::uint16_t>(reader));
        co_return std::tuple<int, Target>{command, asyncio::net::IPv4Address{ip, port}};
    }

    case 3: {
        std::byte length{};
        zero::error::guard(co_await reader.readExactly({&length, 1}));

        std::string host;
        host.resize(std::to_integer<std::size_t>(length));

        zero::error::guard(co_await reader.readExactly(std::as_writable_bytes(std::span{host})));

        const auto port = zero::error::guard(co_await asyncio::binary::readBE<std::uint16_t>(reader));
        co_return std::tuple<int, Target>{command, HostAddress{port, std::move(host)}};
    }

    case 4: {
        std::array<std::byte, 16> ip{};
        zero::error::guard(co_await reader.readExactly(ip));

        const auto port = zero::error::guard(co_await asyncio::binary::readBE<std::uint16_t>(reader));
        co_return std::tuple<int, Target>{command, asyncio::net::IPv6Address{ip, port}};
    }

    default:
        throw zero::error::SystemError{Socks5Error::UNSUPPORTED_ADDRESS_TYPE};
    }
}

asyncio::task::Task<User> readUser(asyncio::IReader &reader) {
    std::byte version{};
    zero::error::guard(co_await reader.readExactly({&version, 1}));

    if (std::to_integer<int>(version) != 1)
        throw zero::error::SystemError{Socks5Error::MISMATCH_AUTHENTICATION_VERSION};

    std::byte length{};
    zero::error::guard(co_await reader.readExactly({&length, 1}));

    std::string username;
    username.resize(std::to_integer<std::size_t>(length));

    zero::error::guard(co_await reader.readExactly(std::as_writable_bytes(std::span{username})));
    zero::error::guard(co_await reader.readExactly({&length, 1}));

    std::string password;
    password.resize(std::to_integer<std::size_t>(length));

    zero::error::guard(co_await reader.readExactly(std::as_writable_bytes(std::span{password})));

    co_return User{std::move(username), std::move(password)};
}

asyncio::task::Task<void>
handshake(asyncio::net::TCPStream &stream, const std::optional<User> account) {
    std::array<std::byte, 2> header{};
    zero::error::guard(co_await stream.readExactly(header));

    std::vector<std::byte> methods(std::to_integer<std::size_t>(header[1]));
    zero::error::guard(co_await stream.readExactly(methods));

    if (!account) {
        constexpr std::array response{std::byte{5}, std::byte{0}};
        zero::error::guard(co_await stream.writeAll(response));
        co_return;
    }

    if (std::ranges::find(methods, std::byte{2}) == methods.end()) {
        constexpr std::array response{std::byte{5}, std::byte{0xff}};
        zero::error::guard(co_await stream.writeAll(response));
        throw zero::error::SystemError{Socks5Error::UNSUPPORTED_AUTHENTICATION_METHOD};
    }

    constexpr std::array response{std::byte{5}, std::byte{2}};
    zero::error::guard(co_await stream.writeAll(response));

    const auto [username, password] = co_await readUser(stream);
    Z_LOG_INFO("Auth user: {}", username);

    if (username != account->username || password != account->password) {
        constexpr std::array result{std::byte{1}, std::byte{1}};
        zero::error::guard(co_await stream.writeAll(result));
        throw zero::error::SystemError{Socks5Error::AUTHENTICATION_FAILED};
    }

    constexpr std::array result{std::byte{1}, std::byte{0}};
    zero::error::guard(co_await stream.writeAll(result));
}

std::optional<std::tuple<Target, std::span<const std::byte>>> unpack(const std::span<const std::byte> data) {
    if (data[2] != std::byte{0}) {
        Z_LOG_ERROR("Fragmentation is not supported");
        return std::nullopt;
    }

    std::optional<std::tuple<Target, std::span<const std::byte>>> packet;

    switch (std::to_integer<int>(data[3])) {
    case 1: {
        asyncio::net::IPv4Address address{};

        address.port = ntohs(*reinterpret_cast<const std::uint16_t *>(data.data() + 8));
        std::ranges::copy(data.subspan(4, 4), address.ip.begin());

        packet = {address, data.subspan(10)};
        break;
    }

    case 3: {
        const auto length = std::to_integer<std::size_t>(data[4]);

        packet = {
            HostAddress{
                ntohs(*reinterpret_cast<const std::uint16_t *>(data.data() + 5 + length)),
                {reinterpret_cast<const char *>(data.data()) + 5, length}
            },
            data.subspan(7 + length)
        };

        break;
    }

    case 4: {
        asyncio::net::IPv6Address address{};

        address.port = ntohs(*reinterpret_cast<const std::uint16_t *>(data.data() + 20));
        std::ranges::copy(data.subspan(4, 16), address.ip.begin());

        packet = {address, data.subspan(22)};
        break;
    }

    default:
        break;
    }

    return packet;
}

asyncio::task::Task<asyncio::net::Address>
setupUDP(
    const std::uint64_t id,
    asyncio::net::UDPSocket &local,
    asyncio::net::tls::TLS<asyncio::net::TCPStream> &remote,
    const Target &source
) {
    std::array<std::byte, 65535> data; // NOLINT(*-pro-type-member-init)
    const auto &[n, from] = zero::error::guard(co_await local.readFrom(data));

    if (!matchSource(source, from))
        throw zero::error::SystemError{Socks5Error::UNEXPECTED_SOURCE_ADDRESS};

    const auto packet = unpack({data.data(), n});

    if (!packet)
        throw zero::error::SystemError{Socks5Error::INVALID_UDP_PACKET};

    const auto &[target, payload] = *packet;

    Z_LOG_INFO("[{}] Send {} bytes to {}", id, payload.size(), target);

    co_await writeTarget(remote, target);
    zero::error::guard(co_await asyncio::binary::writeBE(remote, static_cast<std::uint32_t>(payload.size())));
    zero::error::guard(co_await remote.writeAll(payload));

    co_return from;
}

asyncio::task::Task<void>
UDPToRemote(
    const std::uint64_t id,
    asyncio::net::UDPSocket &local,
    asyncio::IWriter &writer,
    const asyncio::net::Address &client
) {
    while (true) {
        std::array<std::byte, 65535> data; // NOLINT(*-pro-type-member-init)

        const auto &[n, from] = zero::error::guard(co_await local.readFrom(data));

        if (from != client)
            throw zero::error::SystemError{Socks5Error::UNEXPECTED_SOURCE_ADDRESS};

        const auto packet = unpack({data.data(), n});

        if (!packet)
            throw zero::error::SystemError{Socks5Error::INVALID_UDP_PACKET};

        const auto &[target, payload] = *packet;

        Z_LOG_DEBUG("[{}] Send {} bytes to {}", id, payload.size(), target);

        co_await writeTarget(writer, target);
        zero::error::guard(co_await asyncio::binary::writeBE(writer, static_cast<std::uint32_t>(payload.size())));
        zero::error::guard(co_await writer.writeAll(payload));
    }
}

asyncio::task::Task<void>
UDPToClient(
    const std::uint64_t id,
    asyncio::IReader &reader,
    asyncio::net::UDPSocket &local,
    asyncio::net::Address client
) {
    while (true) {
        const auto target = co_await readTarget(reader);
        const auto length = zero::error::guard(co_await asyncio::binary::readBE<std::uint32_t>(reader));

        Z_LOG_DEBUG("[{}] Receive {} bytes from {}", id, length, target);

        std::vector<std::byte> payload(length);
        zero::error::guard(co_await reader.readExactly(payload));

        std::vector response{
            std::byte{0}, std::byte{0},
            std::byte{0}
        };

        if (std::holds_alternative<asyncio::net::IPv4Address>(target)) {
            response.push_back(std::byte{1});

            const auto [ip, port] = std::get<asyncio::net::IPv4Address>(target);
            const auto p = htons(port);

            response.append_range(ip);
            response.append_range(std::span{reinterpret_cast<const std::byte *>(&p), sizeof(std::uint16_t)});
            response.append_range(payload);

            zero::error::guard(co_await local.writeTo(response, client));
            continue;
        }

        response.push_back(std::byte{4});

        const auto &[ip, port, zone] = std::get<asyncio::net::IPv6Address>(target);
        const auto p = htons(port);

        response.append_range(ip);
        response.append_range(std::span{reinterpret_cast<const std::byte *>(&p), sizeof(std::uint16_t)});
        response.append_range(payload);

        zero::error::guard(co_await local.writeTo(response, client));
    }
}

asyncio::task::Task<void>
proxyUDP(
    const std::uint64_t id,
    asyncio::net::TCPStream stream,
    asyncio::net::tls::TLS<asyncio::net::TCPStream> remote,
    const Target source
) {
    auto local = zero::error::guard(std::visit(
        []<typename T>(T arg) -> std::expected<asyncio::net::UDPSocket, std::error_code> {
            if constexpr (!std::is_same_v<T, asyncio::net::UnixAddress>) {
                arg.port = 0;
                return asyncio::net::UDPSocket::bind(arg);
            }
            else {
                std::abort();
            }
        },
        zero::error::guard(stream.localAddress())
    ));

    const auto address = zero::error::guard(local.localAddress());
    Z_LOG_INFO("[{}] UDP associate: {}", id, address);

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

    zero::error::guard(co_await stream.writeAll(response));
    zero::error::guard(co_await asyncio::binary::writeBE(remote, std::to_underlying(ProxyType::UDP)));

    const auto client = co_await setupUDP(id, local, remote, source);
    Z_LOG_INFO("[{}] Client: {}", id, client);

    co_await race(
        asyncio::task::spawn([&]() -> asyncio::task::Task<void> {
            while (true) {
                std::array<std::byte, 1024> data; // NOLINT(*-pro-type-member-init)

                if (const auto n = zero::error::guard(co_await stream.read(data)); n == 0)
                    break;
            }

            co_return;
        }),
        UDPToRemote(id, local, remote, client),
        UDPToClient(id, remote, local, client)
    );

    zero::error::guard(co_await remote.close());
}

asyncio::task::Task<void>
proxyTCP(asyncio::net::TCPStream local, asyncio::net::tls::TLS<asyncio::net::TCPStream> remote, Target target) {
    zero::error::guard(co_await asyncio::binary::writeBE(remote, std::to_underlying(ProxyType::TCP)));
    co_await writeTarget(remote, std::move(target));

    if (const auto status = zero::error::guard(co_await asyncio::binary::readBE<std::int32_t>(remote));
        static_cast<ProxyStatus>(status) != ProxyStatus::SUCCESS) {
        constexpr std::array response{
            std::byte{5},
            std::byte{5},
            std::byte{0},
            std::byte{1},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}
        };

        zero::error::guard(co_await local.writeAll(response));
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

    zero::error::guard(co_await local.writeAll(response));
    zero::error::guard(co_await asyncio::net::copyBidirectional(local, remote));
}

template<typename F>
asyncio::task::Task<void>
handle(const std::uint64_t id, asyncio::net::TCPStream stream, std::optional<User> user, const F connect) {
    Z_LOG_INFO(
        "[{}] Session: fd={} address={} client={}",
        id,
        stream.fd(),
        zero::error::guard(stream.localAddress()),
        zero::error::guard(stream.remoteAddress())
    );

    co_await handshake(stream, std::move(user));

    const auto request = co_await readRequest(stream);
    auto remote = co_await connect();

    switch (auto &[command, target] = request; command) {
    case 1: {
        Z_LOG_INFO("[{}] Target: {}", id, target);
        co_await proxyTCP(std::move(stream), std::move(remote), target);
        break;
    }

    case 3: {
        Z_LOG_INFO("[{}] Source: {}", id, target);
        co_await proxyUDP(id, std::move(stream), std::move(remote), target);
        break;
    }

    default:
        throw zero::error::SystemError{Socks5Error::UNSUPPORTED_COMMAND};
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
            Z_LOG_ERROR("[{}] Unhandled exception: {}", id, e);
        });
    }

    co_await group;
    zero::error::guard(std::move(result));
}

asyncio::task::Task<void> asyncMain(const int argc, char *argv[]) {
    Z_INIT_CONSOLE_LOG(zero::log::Level::INFO_LEVEL);

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

    auto ca = zero::error::guard(co_await asyncio::net::tls::Certificate::loadFile(caFile));
    auto cert = zero::error::guard(co_await asyncio::net::tls::Certificate::loadFile(certFile));
    auto key = zero::error::guard(co_await asyncio::net::tls::PrivateKey::loadFile(keyFile));

    auto context = zero::error::guard(
        asyncio::net::tls::ClientConfig{}
        .rootCAs({std::move(ca)})
        .certKeyPairs({{std::move(cert), std::move(key)}})
        .build()
    );

    auto listener = zero::error::guard(asyncio::net::TCPListener::listen(*bindIP, *bindPort));
    auto signal = asyncio::Signal::make();

    co_await race(
        serve(
            std::move(listener),
            std::move(user),
            [
                =, context = std::move(context)
            ]() -> asyncio::task::Task<asyncio::net::tls::TLS<asyncio::net::TCPStream>> {
                co_return zero::error::guard(
                    co_await asyncio::net::tls::connect(
                        zero::error::guard(co_await asyncio::net::TCPStream::connect(server, port)),
                        context
                    )
                );
            }
        ),
        asyncio::task::spawn([&]() -> asyncio::task::Task<void> {
            zero::error::guard(co_await signal.on(SIGINT));
        })
    );
}
