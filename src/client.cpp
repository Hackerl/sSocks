#include "common.h"
#include <asyncio/net/ssl.h>
#include <asyncio/net/dgram.h>
#include <asyncio/ev/signal.h>
#include <asyncio/event_loop.h>
#include <zero/log.h>
#include <zero/cmdline.h>
#include <csignal>

struct User {
    std::string username;
    std::string password;
};

template<>
std::optional<User> zero::convert<User>(std::string_view str) {
    std::vector<std::string> tokens = zero::strings::split(str, ":");

    if (tokens.size() != 2)
        return std::nullopt;

    return User{zero::strings::trim(tokens[0]), zero::strings::trim(tokens[1])};
}

bool matchSource(const asyncio::net::Address &source, const asyncio::net::Address &from) {
    if (source.index() != from.index())
        return false;

    if (source.index() == 0) {
        auto sourceAddress = std::get<asyncio::net::IPv4Address>(source);
        auto fromAddress = std::get<asyncio::net::IPv4Address>(from);

        if (sourceAddress.port != 0 && sourceAddress.port != fromAddress.port)
            return false;

        if (std::all_of(
                sourceAddress.ip.begin(),
                sourceAddress.ip.end(),
                [](const auto &byte) {
                    return byte == std::byte{0};
                }
        ))
            return true;

        return std::equal(sourceAddress.ip.begin(), sourceAddress.ip.end(), fromAddress.ip.begin());
    }

    auto sourceAddress = std::get<asyncio::net::IPv6Address>(source);
    auto fromAddress = std::get<asyncio::net::IPv6Address>(from);

    if (sourceAddress.port != 0 && sourceAddress.port != fromAddress.port)
        return false;

    if (std::all_of(
            sourceAddress.ip.begin(),
            sourceAddress.ip.end(),
            [](const auto &byte) {
                return byte == std::byte{0};
            }
    ))
        return true;

    return std::equal(sourceAddress.ip.begin(), sourceAddress.ip.end(), fromAddress.ip.begin());
}

zero::async::coroutine::Task<std::tuple<int, Target>, std::error_code>
readRequest(const std::shared_ptr<asyncio::net::stream::IBuffer> &buffer) {
    std::byte header[4];
    auto res = co_await buffer->readExactly(header);

    if (!res)
        co_return tl::unexpected(res.error());

    if (std::to_integer<int>(header[0]) != 5)
        co_return tl::unexpected(Error::UNSUPPORTED_VERSION);

    tl::expected<std::tuple<int, Target>, std::error_code> result;

    int command = std::to_integer<int>(header[1]);
    int type = std::to_integer<int>(header[3]);

    switch (type) {
        case 1: {
            std::array<std::byte, 4> ip = {};
            res = co_await buffer->readExactly(ip);

            if (!res) {
                result = tl::unexpected(res.error());
                break;
            }

            std::byte port[2];
            res = co_await buffer->readExactly(port);

            if (!res) {
                result = tl::unexpected(res.error());
                break;
            }

            result = {command, asyncio::net::IPv4Address{ntohs(*(uint16_t *) port), ip}};
            break;
        }

        case 3: {
            std::byte length[1];
            res = co_await buffer->readExactly(length);

            if (!res) {
                result = tl::unexpected(res.error());
                break;
            }

            std::vector<std::byte> host(std::to_integer<size_t>(length[0]));
            res = co_await buffer->readExactly(host);

            if (!res) {
                result = tl::unexpected(res.error());
                break;
            }

            std::byte port[2];
            res = co_await buffer->readExactly(port);

            if (!res) {
                result = tl::unexpected(res.error());
                break;
            }

            result = {command, HostAddress{ntohs(*(uint16_t *) port), {(const char *) host.data(), host.size()}}};
            break;
        }

        case 4: {
            std::array<std::byte, 16> ip = {};
            res = co_await buffer->readExactly(ip);

            if (!res) {
                result = tl::unexpected(res.error());
                break;
            }

            std::byte port[2];
            res = co_await buffer->readExactly(port);

            if (!res) {
                result = tl::unexpected(res.error());
                break;
            }

            result = {command, asyncio::net::IPv6Address{ntohs(*(uint16_t *) port), ip}};
            break;
        }

        default:
            result = tl::unexpected<std::error_code>(Error::UNSUPPORTED_ADDRESS_TYPE);
            break;
    }

    co_return result;
}

zero::async::coroutine::Task<User, std::error_code>
readUser(const std::shared_ptr<asyncio::net::stream::IBuffer> &buffer) {
    std::byte version[1];
    auto result = co_await buffer->readExactly(version);

    if (!result)
        co_return tl::unexpected(result.error());

    if (std::to_integer<int>(version[0]) != 1)
        co_return tl::unexpected(Error::UNSUPPORTED_AUTH_VERSION);

    std::byte length[1];
    result = co_await buffer->readExactly(length);

    if (!result)
        co_return tl::unexpected(result.error());

    std::vector<std::byte> username(std::to_integer<size_t>(length[0]));
    result = co_await buffer->readExactly(username);

    if (!result)
        co_return tl::unexpected(result.error());

    result = co_await buffer->readExactly(length);

    if (!result)
        co_return tl::unexpected(result.error());

    std::vector<std::byte> password(std::to_integer<size_t>(length[0]));
    result = co_await buffer->readExactly(password);

    if (!result)
        co_return tl::unexpected(result.error());

    co_return User{
            {(const char *) username.data(), username.size()},
            {(const char *) password.data(), password.size()}
    };
}

zero::async::coroutine::Task<void, std::error_code>
handshake(const std::shared_ptr<asyncio::net::stream::IBuffer> &buffer, std::optional<User> account) {
    std::byte header[2];
    auto result = co_await buffer->readExactly(header);

    if (!result)
        co_return tl::unexpected(result.error());

    std::vector<std::byte> methods(std::to_integer<size_t>(header[1]));

    result = co_await buffer->readExactly(methods);

    if (!result)
        co_return tl::unexpected(result.error());

    if (!account) {
        auto response = {std::byte{5}, std::byte{0}};
        co_return co_await buffer->write(response);
    }

    if (std::find(methods.begin(), methods.end(), std::byte{2}) == methods.end()) {
        auto response = {std::byte{5}, std::byte{0xff}};
        co_await buffer->write(response);
        co_return tl::unexpected(Error::UNSUPPORTED_AUTH_METHOD);
    }

    std::array<std::byte, 2> response = {std::byte{5}, std::byte{2}};
    result = co_await buffer->write(response);

    if (!result)
        co_return tl::unexpected(result.error());

    auto user = co_await readUser(buffer);

    if (!user) {
        response = {std::byte{1}, std::byte{1}};
        co_await buffer->write(response);
        co_return tl::unexpected(user.error());
    }

    if (user->username != account->username || user->password != account->password) {
        response = {std::byte{1}, std::byte{1}};
        co_await buffer->write(response);
        co_return tl::unexpected(AUTH_FAILED);
    }

    response = {std::byte{1}, std::byte{0}};
    co_return co_await buffer->write(response);
}

std::optional<std::tuple<Target, std::span<const std::byte>>> unpack(std::span<const std::byte> data) {
    if (data[2] != std::byte{0}) {
        LOG_ERROR("fragmentation is not supported");
        return std::nullopt;
    }

    std::optional<std::tuple<Target, std::span<const std::byte>>> packet;

    switch (std::to_integer<int>(data[3])) {
        case 1: {
            asyncio::net::IPv4Address address = {};

            address.port = ntohs(*(uint16_t *) (data.data() + 8));
            memcpy(address.ip.data(), data.subspan<4, 4>().data(), 4);

            packet = {address, data.subspan(10)};

            break;
        }

        case 3: {
            auto length = std::to_integer<size_t>(data[4]);

            packet = {
                    HostAddress{
                            ntohs(*(uint16_t *) (data.data() + 5 + length)),
                            {(const char *) data.data() + 5, length}
                    },
                    data.subspan(7 + length)
            };

            break;
        }

        case 4: {
            asyncio::net::IPv6Address address = {};

            address.port = ntohs(*(uint16_t *) (data.data() + 20));
            memcpy(address.ip.data(), data.subspan<4, 16>().data(), 16);

            packet = {address, data.subspan(22)};

            break;
        }

        default:
            break;
    }

    return packet;
}

zero::async::coroutine::Task<void> proxyUDP(
        const std::shared_ptr<asyncio::net::stream::IBuffer> &buffer,
        const std::shared_ptr<asyncio::net::stream::IBuffer> &remote,
        const std::optional<asyncio::net::Address> &source
) {
    auto localAddress = buffer->localAddress();

    if (!localAddress) {
        LOG_ERROR("get local address failed[%s]", localAddress.error().message().c_str());
        co_return;
    }

    bool isIPv4 = localAddress->index() == 0;
    std::optional<asyncio::net::Address> bindAddress;

    if (isIPv4)
        bindAddress = asyncio::net::IPv4Address{0, std::get<asyncio::net::IPv4Address>(*localAddress).ip};
    else
        bindAddress = asyncio::net::IPv6Address{0, std::get<asyncio::net::IPv6Address>(*localAddress).ip};

    auto local = asyncio::net::dgram::bind(*bindAddress);

    if (!local) {
        LOG_ERROR("dgram socket bind failed[%s]", local.error().message().c_str());
        co_return;
    }

    auto address = local->localAddress();

    if (!address) {
        LOG_ERROR("get local address failed[%s]", localAddress.error().message().c_str());
        co_return;
    }

    std::vector<std::byte> response = {std::byte{5}, std::byte{0}, std::byte{0}};

    if (isIPv4) {
        response.push_back(std::byte{1});

        auto ipv4Address = std::get<asyncio::net::IPv4Address>(*address);
        unsigned short bindPort = htons(ipv4Address.port);

        response.insert(response.end(), ipv4Address.ip.begin(), ipv4Address.ip.end());
        response.insert(
                response.end(),
                (const std::byte *) &bindPort,
                (const std::byte *) &bindPort + sizeof(unsigned short)
        );
    } else {
        response.push_back(std::byte{4});

        auto ipv6Address = std::get<asyncio::net::IPv6Address>(*address);
        unsigned short bindPort = htons(ipv6Address.port);

        response.insert(response.end(), ipv6Address.ip.begin(), ipv6Address.ip.end());
        response.insert(
                response.end(),
                (const std::byte *) &bindPort,
                (const std::byte *) &bindPort + sizeof(unsigned short)
        );
    }

    auto result = co_await buffer->write(response);

    if (!result) {
        LOG_ERROR("write response failed[%s]", result.error().message().c_str());
        co_return;
    }

    auto type = {std::byte{1}};
    result = co_await remote->write(type);

    if (!result) {
        LOG_ERROR("write address type failed[%s]", result.error().message().c_str());
        co_return;
    }

    std::optional<asyncio::net::Address> client;

    co_await zero::async::coroutine::race(
            [&]() -> zero::async::coroutine::Task<void> {
                co_await buffer->waitClosed();
            }(),
            [&]() -> zero::async::coroutine::Task<void> {
                while (true) {
                    std::byte data[10240];
                    auto result = co_await local->readFrom(data);

                    if (!result) {
                        LOG_ERROR("read packet failed[%s]", result.error().message().c_str());
                        break;
                    }

                    auto &[n, from] = *result;

                    if (source && !matchSource(*source, from)) {
                        LOG_WARNING(
                                "forbidden address[%s does not match %s]",
                                stringify(from).c_str(),
                                stringify(*source).c_str()
                        );
                        break;
                    }

                    if (!client) {
                        LOG_INFO("UDP client[%s]", stringify(from).c_str());
                        client = from;
                    } else if (from != *client) {
                        LOG_WARNING("ignore UDP packet[%s]", stringify(from).c_str());
                        break;
                    }

                    auto packet = unpack({data, n});

                    if (!packet) {
                        LOG_ERROR("invalid UDP packet");
                        break;
                    }

                    const auto &[target, payload] = *packet;

                    LOG_DEBUG(
                            "UDP packet[%s = %zu => %s]",
                            stringify(from).c_str(),
                            payload.size(),
                            stringify(target).c_str()
                    );

                    auto res = co_await writeTarget(remote, target);

                    if (!res) {
                        LOG_ERROR("write target failed[%s]", res.error().message().c_str());
                        break;
                    }

                    auto length = htonl((uint32_t) payload.size());

                    remote->submit({(const std::byte *) &length, sizeof(length)});
                    remote->submit(payload);

                    res = co_await remote->drain();

                    if (!res) {
                        LOG_ERROR("write to remote failed[%s]", res.error().message().c_str());
                        break;
                    }
                }
            }(),
            [&]() -> zero::async::coroutine::Task<void> {
                while (true) {
                    auto target = co_await readTarget(remote);

                    if (!target) {
                        LOG_ERROR("read target failed[%s]", target.error().message().c_str());
                        break;
                    }

                    std::byte length[4];
                    auto result = co_await remote->readExactly(length);

                    if (!result) {
                        LOG_ERROR("read packet length failed[%s]", result.error().message().c_str());
                        break;
                    }

                    std::vector<std::byte> payload(ntohl(*(uint32_t *) length));
                    result = co_await remote->readExactly(payload);

                    if (!result) {
                        LOG_ERROR("read packet failed[%s]", result.error().message().c_str());
                        break;
                    }

                    LOG_DEBUG(
                            "UDP packet[%s <= %zu = %s]",
                            stringify(*client).c_str(),
                            payload.size(),
                            stringify(*target).c_str()
                    );

                    std::vector<std::byte> response = {
                            std::byte{0}, std::byte{0},
                            std::byte{0}
                    };

                    if (target->index() == 1) {
                        response.push_back(std::byte{1});

                        auto ipv4Address = std::get<asyncio::net::IPv4Address>(*target);
                        unsigned short port = htons(ipv4Address.port);

                        response.insert(
                                response.end(),
                                ipv4Address.ip.begin(),
                                ipv4Address.ip.end()
                        );

                        response.insert(
                                response.end(),
                                (const std::byte *) &port,
                                (const std::byte *) &port + sizeof(unsigned short)
                        );

                        response.insert(response.end(), payload.begin(), payload.end());
                        auto res = co_await local->writeTo(response, *client);

                        if (!res) {
                            LOG_ERROR("write packet to client failed[%s]", res.error().message().c_str());
                            break;
                        }

                        continue;
                    }

                    response.push_back(std::byte{4});

                    auto ipv6Address = std::get<asyncio::net::IPv6Address>(*target);
                    unsigned short port = htons(ipv6Address.port);

                    response.insert(
                            response.end(),
                            ipv6Address.ip.begin(),
                            ipv6Address.ip.end()
                    );

                    response.insert(
                            response.end(),
                            (const std::byte *) &port,
                            (const std::byte *) &port + sizeof(unsigned short)
                    );

                    response.insert(response.end(), payload.begin(), payload.end());
                    auto res = co_await local->writeTo(response, *client);

                    if (!res) {
                        LOG_ERROR("write packet to client failed[%s]", res.error().message().c_str());
                        break;
                    }
                }
            }()
    );
}

zero::async::coroutine::Task<void> proxyTCP(
        const std::shared_ptr<asyncio::net::stream::IBuffer> &local,
        const std::shared_ptr<asyncio::net::stream::IBuffer> &remote,
        const Target &target
) {
    auto clientAddress = local->remoteAddress();

    if (!clientAddress) {
        LOG_ERROR("get remote address failed[%s]", clientAddress.error().message().c_str());
        co_return;
    }

    LOG_INFO(
            "TCP proxy[%s <==> %s]",
            stringify(*clientAddress).c_str(),
            stringify(target).c_str()
    );

    auto type = {std::byte{0}};
    auto result = co_await remote->write(type);

    if (!result) {
        LOG_ERROR("write proxy type failed[%s]", result.error().message().c_str());
        co_return;
    }

    result = co_await writeTarget(remote, target);

    if (!result) {
        LOG_ERROR("write target failed[%s]", result.error().message().c_str());
        co_return;
    }

    std::byte status[1];
    result = co_await remote->readExactly(status);

    if (!result) {
        LOG_ERROR("read status code failed[%s]", result.error().message().c_str());
        co_return;
    }

    if (std::to_integer<int>(status[0]) != 0) {
        auto response = {
                std::byte{5},
                std::byte{5},
                std::byte{0},
                std::byte{1},
                std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
                std::byte{0}, std::byte{0}
        };

        result = co_await local->write(response);

        if (!result) {
            LOG_ERROR("write response failed[%s]", result.error().message().c_str());
            co_return;
        }

        co_return;
    }

    LOG_INFO(
            "TCP tunnel[%s <==> %s]",
            stringify(*clientAddress).c_str(),
            stringify(target).c_str()
    );

    auto response = {
            std::byte{5},
            std::byte{0},
            std::byte{0},
            std::byte{1},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}
    };

    result = co_await local->write(response);

    if (!result) {
        LOG_ERROR("write response failed[%s]", result.error().message().c_str());
        co_return;
    }

    co_await zero::async::coroutine::race(asyncio::copy(*local, *remote), asyncio::copy(*remote, *local));
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
    cmdline.addOptional("strict", '\0', "restrict UDP source addresses");

    cmdline.parse(argc, argv);

#ifdef _WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOG_ERROR("WSAStartup failed");
        return -1;
    }
#endif

#ifdef __unix__
    signal(SIGPIPE, SIG_IGN);
#endif

    auto server = cmdline.get<std::string>("server");
    auto port = cmdline.get<unsigned short>("port");
    auto ca = cmdline.get<std::filesystem::path>("ca");
    auto cert = cmdline.get<std::filesystem::path>("cert");
    auto privateKey = cmdline.get<std::filesystem::path>("key");

    auto bindIP = cmdline.getOptional<std::string>("bind-ip");
    auto bindPort = cmdline.getOptional<unsigned short>("bind-port");
    auto user = cmdline.getOptional<User>("user");
    auto strict = cmdline.exist("strict");

    asyncio::run([&]() -> zero::async::coroutine::Task<void> {
        auto context = asyncio::net::ssl::newContext(
                {
                        .ca = ca,
                        .cert = cert,
                        .privateKey = privateKey,
                }
        );

        if (!context) {
            LOG_ERROR("create ssl context failed[%s]", context.error().message().c_str());
            co_return;
        }

        auto listener = asyncio::net::stream::listen(*bindIP, *bindPort);

        if (!listener) {
            LOG_ERROR("listen failed[%s]", listener.error().message().c_str());
            co_return;
        }

        auto signal = asyncio::ev::makeSignal(SIGINT);

        if (!signal) {
            LOG_ERROR("make signal failed[%s]", signal.error().message().c_str());
            co_return;
        }

        auto handle = [&](std::shared_ptr<asyncio::net::stream::IBuffer> buffer) -> zero::async::coroutine::Task<void> {
            auto result = co_await handshake(buffer, user);

            if (!result) {
                LOG_ERROR("handshake failed[%s]", result.error().message().c_str());
                co_return;
            }

            auto request = co_await readRequest(buffer);

            if (!request) {
                LOG_ERROR("read request failed[%s]", request.error().message().c_str());
                co_return;
            }

            auto remote = co_await asyncio::net::ssl::stream::connect(*context, server, port);

            if (!remote) {
                LOG_ERROR("connect to remote failed[%s]", remote.error().message().c_str());
                co_return;
            }

            auto &[command, target] = *request;

            switch (command) {
                case 1: {
                    co_await proxyTCP(buffer, *remote, target);
                    break;
                }

                case 3: {
                    std::optional<asyncio::net::Address> source;

                    if (strict) {
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
                    }

                    co_await proxyUDP(buffer, *remote, source);
                    break;
                }

                default:
                    break;
            }
        };

        co_await zero::async::coroutine::allSettled(
                [&]() -> zero::async::coroutine::Task<void> {
                    co_await signal->on();
                    listener->close();
                }(),
                [&]() -> zero::async::coroutine::Task<void> {
                    while (true) {
                        auto result = co_await listener->accept();

                        if (!result) {
                            LOG_ERROR("accept failed[%s]", result.error().message().c_str());
                            break;
                        }

                        handle(*result);
                    }
                }()
        );
    });

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
