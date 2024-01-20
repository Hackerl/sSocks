#include "common.h"
#include <asyncio/binary.h>
#include <asyncio/net/ssl.h>
#include <asyncio/net/dgram.h>
#include <asyncio/ev/signal.h>
#include <asyncio/event_loop.h>
#include <zero/log.h>
#include <zero/defer.h>
#include <zero/cmdline.h>
#include <csignal>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

struct User {
    std::string username;
    std::string password;
};

template<>
tl::expected<User, std::error_code> zero::scan(const std::string_view input) {
    const auto tokens = strings::split(input, ":");

    if (tokens.size() != 2)
        return tl::unexpected(make_error_code(std::errc::invalid_argument));

    return User{strings::trim(tokens[0]), strings::trim(tokens[1])};
}

bool matchSource(const asyncio::net::Address &source, const asyncio::net::Address &from) {
    if (source.index() != from.index())
        return false;

    if (source.index() == 0) {
        const auto [sourcePort, sourceIP] = std::get<asyncio::net::IPv4Address>(source);
        const auto [fromPort, fromIP] = std::get<asyncio::net::IPv4Address>(from);

        if (sourcePort != 0 && sourcePort != fromPort)
            return false;

        if (std::ranges::all_of(sourceIP, [](const auto &b) { return b == std::byte{0}; }))
            return true;

        return sourceIP == fromIP;
    }

    const auto &[sourcePort, sourceIP, sourceZone] = std::get<asyncio::net::IPv6Address>(source);
    const auto &[fromPort, fromIP, fromZone] = std::get<asyncio::net::IPv6Address>(from);

    if (sourcePort != 0 && sourcePort != fromPort)
        return false;

    if (std::ranges::all_of(sourceIP, [](const auto &b) { return b == std::byte{0}; }))
        return true;

    return sourceIP == fromIP;
}

zero::async::coroutine::Task<std::tuple<int, Target>, std::error_code>
readRequest(asyncio::IBufReader &reader) {
    std::byte header[4];
    CO_EXPECT(co_await reader.readExactly(header));

    if (std::to_integer<int>(header[0]) != 5)
        co_return tl::unexpected(UNSUPPORTED_VERSION);

    const int command = std::to_integer<int>(header[1]);

    switch (std::to_integer<int>(header[3])) {
    case 1: {
        std::array<std::byte, 4> ip = {};
        CO_EXPECT(co_await reader.readExactly(ip));

        const auto port = co_await asyncio::binary::readBE<unsigned short>(reader);
        CO_EXPECT(port);

        co_return std::tuple<int, Target>{command, asyncio::net::IPv4Address{*port, ip}};
    }

    case 3: {
        std::byte length[1];
        CO_EXPECT(co_await reader.readExactly(length));

        std::string host;
        host.resize(std::to_integer<std::size_t>(length[0]));

        CO_EXPECT(co_await reader.readExactly(std::as_writable_bytes(std::span{host})));
        const auto port = co_await asyncio::binary::readBE<unsigned short>(reader);
        CO_EXPECT(port);

        co_return std::tuple<int, Target>{command, HostAddress{*port, std::move(host)}};
    }

    case 4: {
        std::array<std::byte, 16> ip = {};
        CO_EXPECT(co_await reader.readExactly(ip));

        const auto port = co_await asyncio::binary::readBE<unsigned short>(reader);
        CO_EXPECT(port);

        co_return std::tuple<int, Target>{command, asyncio::net::IPv6Address{*port, ip}};
    }

    default:
        co_return tl::unexpected<std::error_code>(UNSUPPORTED_ADDRESS_TYPE);
    }
}

zero::async::coroutine::Task<User, std::error_code> readUser(asyncio::IBufReader &reader) {
    std::byte version[1];
    CO_EXPECT(co_await reader.readExactly(version));

    if (std::to_integer<int>(version[0]) != 1)
        co_return tl::unexpected(UNSUPPORTED_AUTH_VERSION);

    std::byte length[1];
    CO_EXPECT(co_await reader.readExactly(length));

    std::string username;
    username.resize(std::to_integer<std::size_t>(length[0]));

    CO_EXPECT(co_await reader.readExactly(std::as_writable_bytes(std::span{username})));
    CO_EXPECT(co_await reader.readExactly(length));

    std::string password;
    password.resize(std::to_integer<std::size_t>(length[0]));
    CO_EXPECT(co_await reader.readExactly(std::as_writable_bytes(std::span{password})));

    co_return User{std::move(username), std::move(password)};
}

zero::async::coroutine::Task<void, std::error_code> handshake(asyncio::IBuffer &buffer, std::optional<User> account) {
    std::byte header[2];
    CO_EXPECT(co_await buffer.readExactly(header));

    std::vector<std::byte> methods(std::to_integer<std::size_t>(header[1]));
    CO_EXPECT(co_await buffer.readExactly(methods));

    if (!account) {
        constexpr std::array response = {std::byte{5}, std::byte{0}};
        co_return co_await buffer.writeAll(response);
    }

    if (std::ranges::find(methods, std::byte{2}) == methods.end()) {
        constexpr std::array response = {std::byte{5}, std::byte{0xff}};
        CO_EXPECT(co_await buffer.writeAll(response));
        co_return tl::unexpected(UNSUPPORTED_AUTH_METHOD);
    }

    std::array response = {std::byte{5}, std::byte{2}};
    CO_EXPECT(co_await buffer.writeAll(response));

    const auto user = co_await readUser(buffer);
    CO_EXPECT(user);

    LOG_INFO("auth user: {}", user->username);

    if (user->username != account->username || user->password != account->password) {
        response = {std::byte{1}, std::byte{1}};
        CO_EXPECT(co_await buffer.writeAll(response));
        co_return tl::unexpected(AUTH_FAILED);
    }

    response = {std::byte{1}, std::byte{0}};
    co_return co_await buffer.writeAll(response);
}

std::optional<std::tuple<Target, std::span<const std::byte>>> unpack(const std::span<const std::byte> data) {
    if (data[2] != std::byte{0}) {
        LOG_ERROR("fragmentation is not supported");
        return std::nullopt;
    }

    std::optional<std::tuple<Target, std::span<const std::byte>>> packet;

    switch (std::to_integer<int>(data[3])) {
    case 1: {
        asyncio::net::IPv4Address address = {};

        address.port = ntohs(*reinterpret_cast<const std::uint16_t *>(data.data() + 8));
        memcpy(address.ip.data(), data.subspan<4, 4>().data(), 4);

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
        asyncio::net::IPv6Address address = {};

        address.port = ntohs(*reinterpret_cast<const std::uint16_t *>(data.data() + 20));
        memcpy(address.ip.data(), data.subspan<4, 16>().data(), 16);

        packet = {address, data.subspan(22)};
        break;
    }

    default:
        break;
    }

    return packet;
}

zero::async::coroutine::Task<asyncio::net::Address, std::error_code>
setupUDP(asyncio::net::dgram::Socket &local, asyncio::IBuffer &remote, asyncio::net::Address source) {
    std::byte data[10240];
    const auto result = co_await local.readFrom(data);
    CO_EXPECT(result);

    const auto &[n, from] = *result;

    if (!matchSource(source, from))
        co_return tl::unexpected(FORBIDDEN_ADDRESS);

    const auto packet = unpack({data, n});

    if (!packet)
        co_return tl::unexpected(INVALID_UDP_PACKET);

    const auto &[target, payload] = *packet;

    LOG_DEBUG("UDP packet: {} = {} => {}", from, payload.size(), target);

    CO_EXPECT(co_await writeTarget(remote, target));
    CO_EXPECT(co_await asyncio::binary::writeBE(remote, static_cast<std::uint32_t>(payload.size())));
    CO_EXPECT(co_await remote.writeAll(payload));
    CO_EXPECT(co_await remote.flush());

    co_return from;
}

zero::async::coroutine::Task<void, std::error_code>
UDPToRemote(
    const std::shared_ptr<asyncio::net::dgram::Socket> local,
    const std::shared_ptr<asyncio::IBufWriter> writer,
    const asyncio::net::Address client
) {
    while (true) {
        std::byte data[10240];
        const auto result = co_await local->readFrom(data);
        CO_EXPECT(result);

        const auto &[n, from] = *result;

        if (from != client)
            co_return tl::unexpected(FORBIDDEN_ADDRESS);

        const auto packet = unpack({data, n});

        if (!packet)
            co_return tl::unexpected(INVALID_UDP_PACKET);

        const auto &[target, payload] = *packet;
        LOG_DEBUG("UDP packet: {} = {} => {}", from, payload.size(), target);

        CO_EXPECT(co_await writeTarget(*writer, target));
        CO_EXPECT(co_await asyncio::binary::writeBE(*writer, static_cast<std::uint32_t>(payload.size())));
        CO_EXPECT(co_await writer->writeAll(payload));
        CO_EXPECT(co_await writer->flush());
    }
}

zero::async::coroutine::Task<void, std::error_code>
UDPToClient(
    std::shared_ptr<asyncio::IBufReader> reader,
    std::shared_ptr<asyncio::net::dgram::Socket> local,
    asyncio::net::Address client
) {
    while (true) {
        const auto target = co_await readTarget(*reader);
        CO_EXPECT(target);

        const auto length = co_await asyncio::binary::readBE<std::uint32_t>(*reader);
        CO_EXPECT(length);

        std::vector<std::byte> payload(*length);
        CO_EXPECT(co_await reader->readExactly(payload));

        LOG_DEBUG("UDP packet: {} <= {} = {}", client, payload.size(), *target);

        std::vector response = {
            std::byte{0}, std::byte{0},
            std::byte{0}
        };

        if (target->index() == 1) {
            response.push_back(std::byte{1});

            const auto [port, ip] = std::get<asyncio::net::IPv4Address>(*target);
            unsigned short p = htons(port);

            response.insert(response.end(), ip.begin(), ip.end());
            response.insert(
                response.end(),
                reinterpret_cast<const std::byte *>(&p),
                reinterpret_cast<const std::byte *>(&p) + sizeof(unsigned short)
            );

            response.insert(response.end(), payload.begin(), payload.end());
            CO_EXPECT(co_await local->writeTo(response, client));

            continue;
        }

        response.push_back(std::byte{4});

        const auto &[port, ip, zone] = std::get<asyncio::net::IPv6Address>(*target);
        unsigned short p = htons(port);

        response.insert(response.end(), ip.begin(), ip.end());
        response.insert(
            response.end(),
            reinterpret_cast<const std::byte *>(&p),
            reinterpret_cast<const std::byte *>(&p) + sizeof(unsigned short)
        );

        response.insert(response.end(), payload.begin(), payload.end());
        CO_EXPECT(co_await local->writeTo(response, client));
    }
}

zero::async::coroutine::Task<void, std::error_code>
proxyUDP(
    asyncio::net::stream::Buffer buffer,
    asyncio::net::ssl::stream::Buffer remote,
    asyncio::net::Address source
) {
    const auto localAddress = buffer.localAddress();
    CO_EXPECT(localAddress);

    const bool isIPv4 = localAddress->index() == 0;

    std::optional<asyncio::net::Address> bindAddress;

    if (isIPv4)
        bindAddress = asyncio::net::IPv4Address{0, std::get<asyncio::net::IPv4Address>(*localAddress).ip};
    else
        bindAddress = asyncio::net::IPv6Address{0, std::get<asyncio::net::IPv6Address>(*localAddress).ip};

    auto local = asyncio::net::dgram::bind(*bindAddress);
    CO_EXPECT(local);

    const auto address = local->localAddress();
    CO_EXPECT(address);

    std::vector response = {std::byte{5}, std::byte{0}, std::byte{0}};

    if (isIPv4) {
        response.push_back(std::byte{1});

        const auto [port, ip] = std::get<asyncio::net::IPv4Address>(*address);
        unsigned short bindPort = htons(port);

        response.insert(response.end(), ip.begin(), ip.end());
        response.insert(
            response.end(),
            reinterpret_cast<const std::byte *>(&bindPort),
            reinterpret_cast<const std::byte *>(&bindPort) + sizeof(unsigned short)
        );
    }
    else {
        response.push_back(std::byte{4});

        const auto &[port, ip, zone] = std::get<asyncio::net::IPv6Address>(*address);
        unsigned short bindPort = htons(port);

        response.insert(response.end(), ip.begin(), ip.end());
        response.insert(
            response.end(),
            reinterpret_cast<const std::byte *>(&bindPort),
            reinterpret_cast<const std::byte *>(&bindPort) + sizeof(unsigned short)
        );
    }

    CO_EXPECT(co_await buffer.writeAll(response));

    constexpr std::array type = {std::byte{1}};
    CO_EXPECT(co_await remote.writeAll(type));

    const auto client = co_await setupUDP(*local, remote, source);
    CO_EXPECT(client);

    LOG_INFO("UDP client[{}]", *client);
    DEFER(LOG_INFO("UDP proxy finished: {}", *client));

    const auto localSocket = std::make_shared<asyncio::net::dgram::Socket>(std::move(*local));
    const auto remoteBuffer = std::make_shared<asyncio::net::ssl::stream::Buffer>(std::move(remote));

    CO_EXPECT(co_await race(
        [](auto buf) -> zero::async::coroutine::Task<void, std::error_code> {
            while (true) {
                std::byte data[10240];
                CO_EXPECT(co_await buf.read(data));
            }
        }(std::move(buffer)),
        UDPToRemote(localSocket, remoteBuffer, *client),
        UDPToClient(remoteBuffer, localSocket, *client)
    ));

    co_await remoteBuffer->flush();
    co_return tl::expected<void, std::error_code>{};
}

zero::async::coroutine::Task<void, std::error_code>
proxyTCP(asyncio::net::stream::Buffer local, asyncio::net::ssl::stream::Buffer remote, Target target) {
    const auto clientAddress = local.remoteAddress();
    CO_EXPECT(clientAddress);

    LOG_INFO("TCP proxy: {} <==> {}", *clientAddress, target);

    constexpr std::array type = {std::byte{0}};
    CO_EXPECT(co_await remote.writeAll(type));
    CO_EXPECT(co_await writeTarget(remote, target));

    std::byte status[1];
    CO_EXPECT(co_await remote.readExactly(status));

    if (std::to_integer<int>(status[0]) != 0) {
        constexpr std::array response = {
            std::byte{5},
            std::byte{5},
            std::byte{0},
            std::byte{1},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}
        };

        CO_EXPECT(co_await local.writeAll(response));
        co_return tl::expected<void, std::error_code>{};
    }

    LOG_INFO("TCP tunnel: {} <==> {}", *clientAddress, target);

    constexpr std::array response = {
        std::byte{5},
        std::byte{0},
        std::byte{0},
        std::byte{1},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}
    };

    CO_EXPECT(co_await local.writeAll(response));

    const auto localPtr = std::make_shared<asyncio::net::stream::Buffer>(std::move(local));
    const auto remotePtr = std::make_shared<asyncio::net::ssl::stream::Buffer>(std::move(remote));

    CO_EXPECT(co_await copyBidirectional(localPtr, remotePtr));

    co_await localPtr->flush();
    co_await remotePtr->flush();

    co_return tl::expected<void, std::error_code>{};
}

template<typename F>
zero::async::coroutine::Task<void, std::error_code>
handle(asyncio::net::stream::Buffer buffer, const std::optional<User> user, F connect) {
    CO_EXPECT(co_await handshake(buffer, user));
    const auto request = co_await readRequest(buffer);
    CO_EXPECT(request);

    auto remote = co_await connect();
    CO_EXPECT(remote);

    switch (const auto &[command, target] = *request; command) {
    case 1:
        co_return co_await proxyTCP(std::move(buffer), std::move(*remote), target);

    case 3: {
        std::optional<asyncio::net::Address> source;

        switch (target.index()) {
        case 1:
            source = std::get<asyncio::net::IPv4Address>(target);
            break;

        case 2:
            source = std::get<asyncio::net::IPv6Address>(target);
            break;

        default:
            break;
        }

        if (!source)
            co_return tl::unexpected(UNSUPPORTED_ADDRESS_TYPE);

        co_return co_await proxyUDP(std::move(buffer), std::move(*remote), std::move(*source));
    }

    default:
        co_return tl::unexpected(UNSUPPORTED_COMMAND);
    }
}

template<typename F>
zero::async::coroutine::Task<void, std::error_code>
serve(asyncio::net::stream::Listener listener, std::optional<User> user, F connect) {
    while (true) {
        auto buffer = co_await listener.accept();
        CO_EXPECT(buffer);

        const auto local = buffer->localAddress();
        const auto remote = buffer->remoteAddress();

        if (!local || !remote)
            continue;

        LOG_INFO("new connection: {} <==> {}", *local, *remote);

        handle(std::move(*buffer), user, connect).promise()->then(
            [=] {
                LOG_INFO("{} <==> {} disconnect", *local, *remote);
            },
            [=](const std::error_code &ec) {
                LOG_INFO("{} <==> {} disconnect[{}]", *local, *remote, ec.message());
            }
        );
    }
}

int main(int argc, char *argv[]) {
    INIT_CONSOLE_LOG(zero::INFO_LEVEL);

    zero::Cmdline cmdline;

    cmdline.add<std::string>("server", "remote server");
    cmdline.add<unsigned short>("port", "remote server port");

    cmdline.add<std::filesystem::path>("ca", "CA cert path");
    cmdline.add<std::filesystem::path>("cert", "cert path");
    cmdline.add<std::filesystem::path>("key", "private key path");

    cmdline.addOptional<std::string>("bind-ip", '\0', "socks5 server ip", "127.0.0.1");
    cmdline.addOptional<unsigned short>("bind-port", '\0', "socks5 server port", 1080);
    cmdline.addOptional<User>("user", 'u', "socks5 server auth[username:password]");

    cmdline.parse(argc, argv);

#ifdef _WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOG_ERROR("WSAStartup failed");
        return -1;
    }
#endif

#if __unix__ || __APPLE__
    signal(SIGPIPE, SIG_IGN);
#endif

    const auto server = cmdline.get<std::string>("server");
    const auto port = cmdline.get<unsigned short>("port");
    const auto ca = cmdline.get<std::filesystem::path>("ca");
    const auto cert = cmdline.get<std::filesystem::path>("cert");
    const auto privateKey = cmdline.get<std::filesystem::path>("key");

    const auto bindIP = cmdline.getOptional<std::string>("bind-ip");
    const auto bindPort = cmdline.getOptional<unsigned short>("bind-port");
    const auto user = cmdline.getOptional<User>("user");

    asyncio::run([&]() -> zero::async::coroutine::Task<void> {
        const auto context = asyncio::net::ssl::newContext(
            {
                .ca = ca,
                .cert = cert,
                .privateKey = privateKey,
            }
        );

        if (!context) {
            LOG_ERROR("create ssl context failed[{}]", context.error().message());
            co_return;
        }

        auto listener = asyncio::net::stream::listen(*bindIP, *bindPort);

        if (!listener) {
            LOG_ERROR("listen failed[{}]", listener.error().message());
            co_return;
        }

        auto signal = asyncio::ev::makeSignal(SIGINT);

        if (!signal) {
            LOG_ERROR("make signal failed[{}]", signal.error().message());
            co_return;
        }

        co_await race(
            signal->on(),
            serve(
                std::move(*listener),
                user,
                [=] {
                    return asyncio::net::ssl::stream::connect(*context, server, port);
                }
            )
        );
    });

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
