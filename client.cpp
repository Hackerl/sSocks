#include "common.h"
#include <aio/net/ssl.h>
#include <aio/net/dgram.h>
#include <zero/log.h>
#include <zero/cmdline.h>

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

bool matchSource(const aio::net::Address &source, const aio::net::Address &from) {
    if (source.index() != from.index())
        return false;

    if (source.index() == 0) {
        auto sourceAddress = std::get<aio::net::IPv4Address>(source);
        auto fromAddress = std::get<aio::net::IPv4Address>(from);

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

    auto sourceAddress = std::get<aio::net::IPv6Address>(source);
    auto fromAddress = std::get<aio::net::IPv6Address>(from);

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

std::shared_ptr<zero::async::promise::Promise<std::tuple<int, Target>>>
readRequest(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
    return buffer->readExactly(4)->then([=](nonstd::span<const std::byte> data) {
        if (data[0] != std::byte{5})
            return zero::async::promise::reject<std::tuple<int, Target>>(
                    {-1, "unsupported version"}
            );

        std::shared_ptr<zero::async::promise::Promise<Target>> promise;

        switch (std::to_integer<int>(data[3])) {
            case 1:
                promise = buffer->readExactly(4)->then([=](const std::vector<std::byte> &data) {
                    return buffer->readExactly(2)->then([ip = data](nonstd::span<const std::byte> data) -> Target {
                        aio::net::IPv4Address address = {};

                        address.port = ntohs(*(uint16_t *) data.data());
                        memcpy(address.ip.data(), ip.data(), 4);

                        return address;
                    });
                });

                break;

            case 3:
                promise = buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
                    return buffer->readExactly(std::to_integer<size_t>(data[0]));
                })->then([=](nonstd::span<const std::byte> data) {
                    std::string host = std::string{(const char *) data.data(), data.size()};
                    return buffer->readExactly(2)->then(
                            [host = std::move(host)](nonstd::span<const std::byte> data) -> Target {
                                return HostAddress{ntohs(*(uint16_t *) data.data()), host};
                            }
                    );
                });

                break;

            case 4:
                promise = buffer->readExactly(16)->then([=](const std::vector<std::byte> &data) {
                    return buffer->readExactly(2)->then([ip = data](nonstd::span<const std::byte> data) -> Target {
                        aio::net::IPv6Address address = {};

                        address.port = ntohs(*(uint16_t *) data.data());
                        memcpy(address.ip.data(), ip.data(), 16);

                        return address;
                    });
                });

                break;

            default:
                break;
        }

        if (!promise)
            return zero::async::promise::reject<std::tuple<int, Target>>(
                    {-1, "unsupported address type"}
            );

        return promise->then([=](const Target &address) {
            return std::tuple<int, Target>{std::to_integer<int>(data[1]), address};
        });
    });
}

std::shared_ptr<zero::async::promise::Promise<User>>
readUser(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
    return buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
        if (data[0] != std::byte{1}) {
            auto response = {std::byte{1}, std::byte{1}};
            return buffer->write(response)->then([]() {
                return zero::async::promise::reject<User>({-1, "unsupported auth version"});
            });
        }

        return buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
            return buffer->readExactly(std::to_integer<size_t>(data[0]));
        })->then([=](nonstd::span<const std::byte> data) {
            std::string username = {(const char *) data.data(), data.size()};

            return buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
                return buffer->readExactly(std::to_integer<size_t>(data[0]));
            })->then([=, username = std::move(username)](nonstd::span<const std::byte> data) {
                return User{username, {(const char *) data.data(), data.size()}};
            });
        });
    });
}

std::shared_ptr<zero::async::promise::Promise<void>>
handshake(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer, std::optional<User> user) {
    return buffer->readExactly(2)->then([=](nonstd::span<const std::byte> data) {
        if (data[0] != std::byte{5})
            return zero::async::promise::reject<std::vector<std::byte>>({-1, "unsupported version"});

        return buffer->readExactly(std::to_integer<size_t>(data[1]));
    })->then([=](nonstd::span<const std::byte> data) {
        if (!user) {
            auto response = {std::byte{5}, std::byte{0}};
            return buffer->write(response);
        }

        if (std::find(data.begin(), data.end(), std::byte{2}) == data.end()) {
            auto response = {std::byte{5}, std::byte{0xff}};
            return buffer->write(response)->then([]() {
                return zero::async::promise::reject<void>({-1, "unsupported method"});
            });
        }

        auto response = {std::byte{5}, std::byte{2}};

        return buffer->write(response)->then([=]() {
            return readUser(buffer);
        })->then([=](const User &input) {
            if (input.username != user->username || input.password != user->password) {
                auto response = {std::byte{1}, std::byte{1}};
                return buffer->write(response)->then([]() {
                    return zero::async::promise::reject<void>({-1, "auth failed"});
                });
            }

            auto response = {std::byte{1}, std::byte{0}};
            return buffer->write(response);
        });
    });
}

std::optional<std::tuple<Target, nonstd::span<const std::byte>>>
unpack(nonstd::span<const std::byte> data) {
    if (data[2] != std::byte{0}) {
        LOG_ERROR("fragmentation is not supported");
        return std::nullopt;
    }

    std::optional<std::tuple<Target, nonstd::span<const std::byte>>> packet;

    switch (std::to_integer<int>(data[3])) {
        case 1: {
            aio::net::IPv4Address address = {};

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
            aio::net::IPv6Address address = {};

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

std::shared_ptr<zero::async::promise::Promise<void>> proxyUDP(
        const std::shared_ptr<aio::Context> &context,
        const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer,
        const zero::ptr::RefPtr<aio::net::stream::IBuffer> &remote,
        const aio::net::Address &source
) {
    std::optional<aio::net::Address> localAddress = buffer->localAddress();

    if (!localAddress)
        return zero::async::promise::reject<void>({-1, aio::lastError()});

    bool isIPv4 = localAddress->index() == 0;
    zero::ptr::RefPtr<aio::net::dgram::Socket> local;

    if (isIPv4)
        local = aio::net::dgram::bind(
                context,
                aio::net::IPv4Address{
                        0,
                        std::get<aio::net::IPv4Address>(*localAddress).ip
                }
        );
    else
        local = aio::net::dgram::bind(
                context,
                aio::net::IPv6Address{
                        0,
                        std::get<aio::net::IPv6Address>(*localAddress).ip
                }
        );

    if (!local)
        return zero::async::promise::reject<void>({-1, aio::lastError()});

    std::optional<aio::net::Address> bindAddress = local->localAddress();

    if (!bindAddress)
        return zero::async::promise::reject<void>({-1, aio::lastError()});

    std::vector<std::byte> response = {std::byte{5}, std::byte{0}, std::byte{0}};

    if (isIPv4) {
        response.push_back(std::byte{1});

        auto ipv4Address = std::get<aio::net::IPv4Address>(*bindAddress);
        unsigned short bindPort = htons(ipv4Address.port);

        response.insert(response.end(), ipv4Address.ip.begin(), ipv4Address.ip.end());
        response.insert(
                response.end(),
                (const std::byte *) &bindPort,
                (const std::byte *) &bindPort + sizeof(unsigned short)
        );
    } else {
        response.push_back(std::byte{4});

        auto ipv6Address = std::get<aio::net::IPv6Address>(*bindAddress);
        unsigned short bindPort = htons(ipv6Address.port);

        response.insert(response.end(), ipv6Address.ip.begin(), ipv6Address.ip.end());
        response.insert(
                response.end(),
                (const std::byte *) &bindPort,
                (const std::byte *) &bindPort + sizeof(unsigned short)
        );
    }

    return buffer->write(response)->then([=]() {
        auto type = {std::byte{1}};
        return remote->write(type);
    })->then([=]() {
        std::shared_ptr<std::optional<aio::net::Address>> client = std::make_shared<std::optional<aio::net::Address>>();

        return zero::async::promise::race(
                buffer->waitClosed(),
                zero::async::promise::loop<void>([=](const auto &loop) {
                    local->readFrom(10240)->then(
                            [=](nonstd::span<const std::byte> data, const aio::net::Address &from) {
                                if (!matchSource(source, from))
                                    return zero::async::promise::resolve<void>();

                                if (!*client)
                                    *client = from;
                                else if (from != **client)
                                    return zero::async::promise::resolve<void>();

                                auto packet = unpack(data);

                                if (!packet)
                                    return zero::async::promise::reject<void>(
                                            {-1, "invalid packet"}
                                    );

                                const auto &[target, payload] = *packet;

                                writeTarget(remote, target);

                                auto length = htonl((uint32_t) payload.size());

                                remote->submit({(const std::byte *) &length, sizeof(length)});
                                remote->submit(payload);

                                return remote->drain();
                            }
                    )->then([=]() {
                        P_CONTINUE(loop);
                    }, [=](const zero::async::promise::Reason &reason) {
                        P_BREAK_E(loop, reason);
                    });
                }),
                zero::async::promise::loop<void>([=](const auto &loop) {
                    readTarget(remote)->then([=](const Target &target) {
                        return remote->readExactly(4)->then([=](nonstd::span<const std::byte> data) {
                            return remote->readExactly(ntohl(*(uint32_t *) data.data()));
                        })->then([=](nonstd::span<const std::byte> data) {
                            std::vector<std::byte> response = {
                                    std::byte{0}, std::byte{0},
                                    std::byte{0}
                            };

                            if (target.index() == 1) {
                                response.push_back(std::byte{1});

                                auto ipv4Address = std::get<aio::net::IPv4Address>(target);
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

                                response.insert(response.end(), data.begin(), data.end());

                                return local->writeTo(response, **client);
                            }

                            response.push_back(std::byte{4});

                            auto ipv6Address = std::get<aio::net::IPv6Address>(target);
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

                            response.insert(response.end(), data.begin(), data.end());

                            return local->writeTo(response, **client);
                        });
                    })->then([=]() {
                        P_CONTINUE(loop);
                    }, [=](const zero::async::promise::Reason &reason) {
                        P_BREAK_E(loop, reason);
                    });
                })
        );
    })->finally([=]() {
        local->close();
    });
}

std::shared_ptr<zero::async::promise::Promise<void>> proxyTCP(
        const std::shared_ptr<aio::Context> &context,
        const zero::ptr::RefPtr<aio::net::stream::IBuffer> &local,
        const zero::ptr::RefPtr<aio::net::stream::IBuffer> &remote,
        const Target &target
) {
    auto type = {std::byte{0}};

    return remote->write(type)->then([=]() {
        return writeTarget(remote, target);
    })->then([=]() {
        return remote->readExactly(1);
    })->then([=](nonstd::span<const std::byte> data) {
        if (data[0] != std::byte{0}) {
            auto response = {
                    std::byte{5},
                    std::byte{5},
                    std::byte{0},
                    std::byte{1},
                    std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
                    std::byte{0}, std::byte{0}
            };

            return local->write(response)->then([=]() {
                return zero::async::promise::reject<void>({-1, "proxy failed"});
            });
        }

        auto response = {
                std::byte{5},
                std::byte{0},
                std::byte{0},
                std::byte{1},
                std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
                std::byte{0}, std::byte{0}
        };

        return local->write(response)->then([=] {
            return aio::tunnel(local, remote);
        });
    });
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
    cmdline.addOptional<User>("user", 'u', "socks5 server auth(username:password)]");

    cmdline.parse(argc, argv);

#ifdef _WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOG_ERROR("WSAStartup failed");
        return -1;
    }
#endif

    auto server = cmdline.get<std::string>("server");
    auto port = cmdline.get<unsigned short>("port");
    auto bindIP = cmdline.getOptional<std::string>("bind-ip");
    auto bindPort = cmdline.getOptional<unsigned short>("bind-port");
    auto user = cmdline.getOptional<User>("user");

    std::shared_ptr<aio::Context> context = aio::newContext();

    if (!context)
        return -1;

    aio::net::ssl::Config config = {};

    config.ca = cmdline.get<std::filesystem::path>("ca");
    config.cert = cmdline.get<std::filesystem::path>("cert");
    config.privateKey = cmdline.get<std::filesystem::path>("key");

    std::shared_ptr<aio::net::ssl::Context> ctx = aio::net::ssl::newContext(config);

    if (!ctx)
        return -1;

    zero::ptr::RefPtr<aio::net::stream::Listener> listener = aio::net::stream::listen(context, *bindIP, *bindPort);

    if (!listener)
        return -1;

    zero::async::promise::loop<void>([=](const auto &loop) {
        listener->accept()->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
            handshake(buffer, user)->then([=]() {
                return readRequest(buffer);
            })->then([=](int command, const Target &target) {
                LOG_INFO("proxy request: %d %s", command, stringify(target).c_str());

                std::shared_ptr<zero::async::promise::Promise<void>> promise;

                switch (command) {
                    case 1: {
                        promise = aio::net::ssl::stream::connect(
                                context,
                                server,
                                port,
                                ctx
                        )->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &remote) {
                            return proxyTCP(context, buffer, remote, target)->finally([=]() {
                                remote->close();
                            });
                        });

                        break;
                    }

                    case 3: {
                        std::optional<aio::net::Address> source;

                        switch (target.index()) {
                            case 1:
                                source = std::get<aio::net::IPv4Address>(target);
                                break;

                            case 2:
                                source = std::get<aio::net::IPv6Address>(target);
                                break;

                            default:
                                break;
                        }

                        if (!source) {
                            promise = zero::async::promise::reject<void>({-1, "unsupported address type"});
                            break;
                        }

                        promise = aio::net::ssl::stream::connect(
                                context,
                                server,
                                port,
                                ctx
                        )->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &remote) {
                            return proxyUDP(context, buffer, remote, *source)->finally([=]() {
                                remote->close();
                            });
                        });

                        break;
                    }

                    default:
                        break;
                }

                if (!promise)
                    return zero::async::promise::reject<void>({-1, "unsupported command"});

                return promise;
            })->fail([](const zero::async::promise::Reason &reason) {
                LOG_INFO("%s", reason.message.c_str());
            })->finally([=]() {
                buffer->close();
            });
        })->then([=]() {
            P_CONTINUE(loop);
        }, [=](const zero::async::promise::Reason &reason) {
            P_BREAK_E(loop, reason);
        });
    })->fail([](const zero::async::promise::Reason &reason) {
        LOG_ERROR("%s", reason.message.c_str());
    })->finally([=]() {
        context->loopBreak();
    });

    context->dispatch();

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
