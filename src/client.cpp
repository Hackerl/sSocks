#include "common.h"
#include <asyncio/signal.h>
#include <asyncio/net/tls.h>
#include <asyncio/net/dgram.h>
#include <asyncio/net/stream.h>
#include <zero/log.h>
#include <zero/cmdline.h>

struct User {
    std::string username;
    std::string password;
};

DEFINE_ERROR_CODE_EX(
    ScanUserError,
    "zero::scan<User>",
    INVALID_FORMAT, "invalid user information", std::errc::invalid_argument
)

DECLARE_ERROR_CODE(ScanUserError)
DEFINE_ERROR_CATEGORY_INSTANCES(ScanUserError)

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

DEFINE_ERROR_CODE(
    Socks5Error,
    "socks5",
    MISMATCH_VERSION, "mismatch version",
    UNSUPPORTED_COMMAND, "unsupported command",
    UNSUPPORTED_ADDRESS_TYPE, "unsupported address type",
    MISMATCH_AUTHENTICATION_VERSION, "mismatch authentication version",
    UNSUPPORTED_AUTHENTICATION_METHOD, "unsupported authentication method",
    AUTHENTICATION_FAILED, "authentication failed",
    UNEXPECTED_SOURCE_ADDRESS, "unexpected source address",
    INVALID_UDP_PACKET, "invalid UDP packet"
)

DECLARE_ERROR_CODE(Socks5Error)
DEFINE_ERROR_CATEGORY_INSTANCES(Socks5Error)

asyncio::task::Task<std::tuple<int, Target>, std::error_code>
readRequest(asyncio::IReader &reader) {
    std::array<std::byte, 4> header{};
    CO_EXPECT(co_await reader.readExactly(header));

    if (std::to_integer<int>(header[0]) != 5)
        co_return std::unexpected{Socks5Error::MISMATCH_VERSION};

    const auto command = std::to_integer<int>(header[1]);

    switch (std::to_integer<int>(header[3])) {
    case 1: {
        std::array<std::byte, 4> ip{};
        CO_EXPECT(co_await reader.readExactly(ip));

        const auto port = co_await asyncio::binary::readBE<std::uint16_t>(reader);
        CO_EXPECT(port);

        co_return std::tuple<int, Target>{command, asyncio::net::IPv4Address{ip, *port}};
    }

    case 3: {
        std::byte length{};
        CO_EXPECT(co_await reader.readExactly({&length, 1}));

        std::string host;
        host.resize(std::to_integer<std::size_t>(length));

        CO_EXPECT(co_await reader.readExactly(std::as_writable_bytes(std::span{host})));

        const auto port = co_await asyncio::binary::readBE<std::uint16_t>(reader);
        CO_EXPECT(port);

        co_return std::tuple<int, Target>{command, HostAddress{*port, std::move(host)}};
    }

    case 4: {
        std::array<std::byte, 16> ip{};
        CO_EXPECT(co_await reader.readExactly(ip));

        const auto port = co_await asyncio::binary::readBE<std::uint16_t>(reader);
        CO_EXPECT(port);

        co_return std::tuple<int, Target>{command, asyncio::net::IPv6Address{ip, *port}};
    }

    default:
        co_return std::unexpected{Socks5Error::UNSUPPORTED_ADDRESS_TYPE};
    }
}

asyncio::task::Task<User, std::error_code> readUser(asyncio::IReader &reader) {
    std::byte version{};
    CO_EXPECT(co_await reader.readExactly({&version, 1}));

    if (std::to_integer<int>(version) != 1)
        co_return std::unexpected{Socks5Error::MISMATCH_AUTHENTICATION_VERSION};

    std::byte length{};
    CO_EXPECT(co_await reader.readExactly({&length, 1}));

    std::string username;
    username.resize(std::to_integer<std::size_t>(length));

    CO_EXPECT(co_await reader.readExactly(std::as_writable_bytes(std::span{username})));
    CO_EXPECT(co_await reader.readExactly({&length, 1}));

    std::string password;
    password.resize(std::to_integer<std::size_t>(length));

    CO_EXPECT(co_await reader.readExactly(std::as_writable_bytes(std::span{password})));

    co_return User{std::move(username), std::move(password)};
}

asyncio::task::Task<void, std::error_code>
handshake(asyncio::net::TCPStream &stream, const std::optional<User> account) {
    std::array<std::byte, 2> header{};
    CO_EXPECT(co_await stream.readExactly(header));

    std::vector<std::byte> methods(std::to_integer<std::size_t>(header[1]));
    CO_EXPECT(co_await stream.readExactly(methods));

    if (!account) {
        constexpr std::array response{std::byte{5}, std::byte{0}};
        co_return co_await stream.writeAll(response);
    }

    if (std::ranges::find(methods, std::byte{2}) == methods.end()) {
        constexpr std::array response{std::byte{5}, std::byte{0xff}};
        CO_EXPECT(co_await stream.writeAll(response));
        co_return std::unexpected{Socks5Error::UNSUPPORTED_AUTHENTICATION_METHOD};
    }

    constexpr std::array response{std::byte{5}, std::byte{2}};
    CO_EXPECT(co_await stream.writeAll(response));

    const auto user = co_await readUser(stream);
    CO_EXPECT(user);

    LOG_INFO("auth user: {}", user->username);

    if (user->username != account->username || user->password != account->password) {
        constexpr std::array result{std::byte{1}, std::byte{1}};
        CO_EXPECT(co_await stream.writeAll(result));
        co_return std::unexpected{Socks5Error::AUTHENTICATION_FAILED};
    }

    constexpr std::array result{std::byte{1}, std::byte{0}};
    co_return co_await stream.writeAll(result);
}

std::optional<std::tuple<Target, std::span<const std::byte>>> unpack(const std::span<const std::byte> data) {
    if (data[2] != std::byte{0}) {
        LOG_ERROR("fragmentation is not supported");
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

asyncio::task::Task<asyncio::net::Address, std::error_code>
setupUDP(
    const std::uint64_t id,
    asyncio::net::UDPSocket &local,
    asyncio::net::tls::TLS<asyncio::net::TCPStream> &remote,
    const Target &source
) {
    std::array<std::byte, 65535> data; // NOLINT(*-pro-type-member-init)

    const auto result = co_await local.readFrom(data);
    CO_EXPECT(result);

    const auto &[n, from] = *result;

    if (!matchSource(source, from))
        co_return std::unexpected{Socks5Error::UNEXPECTED_SOURCE_ADDRESS};

    const auto packet = unpack({data.data(), n});

    if (!packet)
        co_return std::unexpected{Socks5Error::INVALID_UDP_PACKET};

    const auto &[target, payload] = *packet;

    LOG_INFO("[{}] send {} bytes to {}", id, payload.size(), target);

    CO_EXPECT(co_await writeTarget(remote, target));
    CO_EXPECT(co_await asyncio::binary::writeBE(remote, static_cast<std::uint32_t>(payload.size())));
    CO_EXPECT(co_await remote.writeAll(payload));

    co_return from;
}

asyncio::task::Task<void, std::error_code>
UDPToRemote(
    const std::uint64_t id,
    asyncio::net::UDPSocket &local,
    asyncio::IWriter &writer,
    const asyncio::net::Address &client
) {
    while (true) {
        std::array<std::byte, 65535> data; // NOLINT(*-pro-type-member-init)

        const auto result = co_await local.readFrom(data);
        CO_EXPECT(result);

        const auto &[n, from] = *result;

        if (from != client)
            co_return std::unexpected{Socks5Error::UNEXPECTED_SOURCE_ADDRESS};

        const auto packet = unpack({data.data(), n});

        if (!packet)
            co_return std::unexpected{Socks5Error::INVALID_UDP_PACKET};

        const auto &[target, payload] = *packet;

        LOG_DEBUG("[{}] send {} bytes to {}", id, payload.size(), target);

        CO_EXPECT(co_await writeTarget(writer, target));
        CO_EXPECT(co_await asyncio::binary::writeBE(writer, static_cast<std::uint32_t>(payload.size())));
        CO_EXPECT(co_await writer.writeAll(payload));
    }
}

asyncio::task::Task<void, std::error_code>
UDPToClient(
    const std::uint64_t id,
    asyncio::IReader &reader,
    asyncio::net::UDPSocket &local,
    asyncio::net::Address client
) {
    while (true) {
        const auto target = co_await readTarget(reader);
        CO_EXPECT(target);

        const auto length = co_await asyncio::binary::readBE<std::uint32_t>(reader);
        CO_EXPECT(length);

        LOG_DEBUG("[{}] receive {} bytes from {}", id, *length, *target);

        std::vector<std::byte> payload(*length);
        CO_EXPECT(co_await reader.readExactly(payload));

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

            CO_EXPECT(co_await local.writeTo(response, client));
            continue;
        }

        response.push_back(std::byte{4});

        const auto &[ip, port, zone] = std::get<asyncio::net::IPv6Address>(*target);
        const auto p = htons(port);

        response.append_range(ip);
        response.append_range(std::span{reinterpret_cast<const std::byte *>(&p), sizeof(std::uint16_t)});
        response.append_range(payload);

        CO_EXPECT(co_await local.writeTo(response, client));
    }
}

asyncio::task::Task<void, std::error_code>
proxyUDP(
    const std::uint64_t id,
    asyncio::net::TCPStream stream,
    asyncio::net::tls::TLS<asyncio::net::TCPStream> remote,
    const Target source
) {
    auto bindAddress = stream.localAddress();
    CO_EXPECT(bindAddress);

    auto local = std::visit(
        []<typename T>(T arg) -> std::expected<asyncio::net::UDPSocket, std::error_code> {
            if constexpr (!std::is_same_v<T, asyncio::net::UnixAddress>) {
                arg.port = 0;
                return asyncio::net::UDPSocket::bind(arg);
            }
            else {
                std::abort();
            }
        },
        *std::move(bindAddress)
    );
    CO_EXPECT(local);

    const auto localAddress = local->localAddress();
    CO_EXPECT(localAddress);

    LOG_INFO("[{}] udp associate: {}", id, *localAddress);

    std::vector response{std::byte{5}, std::byte{0}, std::byte{0}};

    if (std::holds_alternative<asyncio::net::IPv4Address>(*localAddress)) {
        response.push_back(std::byte{1});

        const auto [ip, port] = std::get<asyncio::net::IPv4Address>(*localAddress);
        const auto bindPort = htons(port);

        response.append_range(ip);
        response.append_range(std::span{reinterpret_cast<const std::byte *>(&bindPort), sizeof(std::uint16_t)});
    }
    else {
        response.push_back(std::byte{4});

        const auto &[ip, port, zone] = std::get<asyncio::net::IPv6Address>(*localAddress);
        const auto bindPort = htons(port);

        response.append_range(ip);
        response.append_range(std::span{reinterpret_cast<const std::byte *>(&bindPort), sizeof(std::uint16_t)});
    }

    CO_EXPECT(co_await stream.writeAll(response));
    CO_EXPECT(co_await asyncio::binary::writeBE(remote, std::to_underlying(ProxyType::UDP)));

    const auto client = co_await setupUDP(id, *local, remote, source);
    CO_EXPECT(client);

    LOG_INFO("[{}] client: {}", id, *client);

    co_return co_await race(
        asyncio::task::spawn([&]() -> asyncio::task::Task<void, std::error_code> {
            while (true) {
                std::array<std::byte, 1024> data; // NOLINT(*-pro-type-member-init)

                const auto n = co_await stream.read(data);
                CO_EXPECT(n);

                if (*n == 0)
                    break;
            }

            co_return {};
        }),
        UDPToRemote(id, *local, remote, *client),
        UDPToClient(id, remote, *local, *client)
    ).andThen([&] {
        return remote.close();
    });
}

asyncio::task::Task<void, std::error_code>
proxyTCP(asyncio::net::TCPStream local, asyncio::net::tls::TLS<asyncio::net::TCPStream> remote, Target target) {
    CO_EXPECT(co_await asyncio::binary::writeBE(remote, std::to_underlying(ProxyType::TCP)));
    CO_EXPECT(co_await writeTarget(remote, std::move(target)));

    const auto status = co_await asyncio::binary::readBE<std::int32_t>(remote);
    CO_EXPECT(status);

    if (static_cast<ProxyStatus>(*status) != ProxyStatus::SUCCESS) {
        constexpr std::array response{
            std::byte{5},
            std::byte{5},
            std::byte{0},
            std::byte{1},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}
        };

        CO_EXPECT(co_await local.writeAll(response));
        co_return std::expected<void, std::error_code>{};
    }

    constexpr std::array response{
        std::byte{5},
        std::byte{0},
        std::byte{0},
        std::byte{1},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}
    };

    CO_EXPECT(co_await local.writeAll(response));
    CO_EXPECT(co_await asyncio::net::copyBidirectional(local, remote));

    co_return {};
}

template<typename F>
asyncio::task::Task<void, std::error_code>
handle(const std::uint64_t id, asyncio::net::TCPStream stream, std::optional<User> user, const F connect) {
    CO_EXPECT(co_await handshake(stream, std::move(user)));

    const auto request = co_await readRequest(stream);
    CO_EXPECT(request);

    auto remote = co_await connect();
    CO_EXPECT(remote);

    switch (auto &[command, target] = *request; command) {
    case 1: {
        LOG_INFO("[{}] target: {}", id, target);
        co_return co_await proxyTCP(std::move(stream), *std::move(remote), target);
    }

    case 3: {
        LOG_INFO("[{}] source: {}", id, target);
        co_return co_await proxyUDP(id, std::move(stream), *std::move(remote), target);
    }

    default:
        co_return std::unexpected{Socks5Error::UNSUPPORTED_COMMAND};
    }
}

template<typename F>
asyncio::task::Task<void, std::error_code>
serve(asyncio::net::TCPListener listener, const std::optional<User> user, const F connect) {
    std::expected<void, std::error_code> result;
    asyncio::task::TaskGroup group;

    while (true) {
        auto stream = co_await listener.accept();

        if (!stream) {
            result = std::unexpected{stream.error()};
            break;
        }

        const auto localAddress = stream->localAddress();
        const auto remoteAddress = stream->remoteAddress();

        if (!localAddress || !remoteAddress)
            continue;

        static std::uint64_t counter;
        const auto id = counter++;

        LOG_INFO("[{}] session: fd={} address={} client={}", id, stream->fd(), *localAddress, *remoteAddress);

        auto task = handle(id, *std::move(stream), user, connect);
        group.add(task);

        task.future().fail([=](const auto &ec) {
            LOG_ERROR("[{}] unhandled error: {:s} ({})", id, ec, ec);
        });
    }

    co_await group;
    co_return result;
}

asyncio::task::Task<void, std::error_code> asyncMain(const int argc, char *argv[]) {
    INIT_CONSOLE_LOG(zero::log::Level::INFO_LEVEL);

    zero::Cmdline cmdline;

    cmdline.add<std::string>("server", "remote server");
    cmdline.add<std::uint16_t>("port", "remote server port");

    cmdline.add<std::filesystem::path>("ca", "CA cert path");
    cmdline.add<std::filesystem::path>("cert", "cert path");
    cmdline.add<std::filesystem::path>("key", "private key path");

    cmdline.addOptional<std::string>("bind-ip", '\0', "socks5 server ip", "127.0.0.1");
    cmdline.addOptional<std::uint16_t>("bind-port", '\0', "socks5 server port", 1080);
    cmdline.addOptional<User>("user", '\0', "socks5 server auth[username:password]");

    cmdline.parse(argc, argv);

    const auto server = cmdline.get<std::string>("server");
    const auto port = cmdline.get<std::uint16_t>("port");
    const auto caFile = cmdline.get<std::filesystem::path>("ca");
    const auto certFile = cmdline.get<std::filesystem::path>("cert");
    const auto keyFile = cmdline.get<std::filesystem::path>("key");

    const auto bindIP = cmdline.getOptional<std::string>("bind-ip");
    const auto bindPort = cmdline.getOptional<std::uint16_t>("bind-port");
    auto user = cmdline.getOptional<User>("user");

    auto ca = co_await asyncio::net::tls::Certificate::loadFile(caFile);
    CO_EXPECT(ca);

    auto cert = co_await asyncio::net::tls::Certificate::loadFile(certFile);
    CO_EXPECT(cert);

    auto key = co_await asyncio::net::tls::PrivateKey::loadFile(keyFile);
    CO_EXPECT(key);

    auto context = asyncio::net::tls::ClientConfig{}
                   .rootCAs({*std::move(ca)})
                   .certKeyPairs({{*std::move(cert), *std::move(key)}})
                   .build();
    CO_EXPECT(context);

    auto listener = asyncio::net::TCPListener::listen(*bindIP, *bindPort);
    CO_EXPECT(listener);

    auto signal = asyncio::Signal::make();
    CO_EXPECT(signal);

    co_return co_await race(
        serve(
            *std::move(listener),
            std::move(user),
            [
                =, context = *std::move(context)
            ]() -> asyncio::task::Task<asyncio::net::tls::TLS<asyncio::net::TCPStream>, std::error_code> {
                auto stream = co_await asyncio::net::TCPStream::connect(server, port);
                CO_EXPECT(stream);
                co_return co_await asyncio::net::tls::connect(*std::move(stream), context);
            }
        ),
        signal->on(SIGINT).transform([](const int) {
        })
    );
}
