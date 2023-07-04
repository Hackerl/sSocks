#include "common.h"
#include <aio/net/ssl.h>
#include <aio/net/dgram.h>
#include <aio/net/dns.h>
#include <zero/log.h>
#include <zero/cmdline.h>

std::shared_ptr<zero::async::promise::Promise<std::vector<aio::net::Address>>> resolve(
        const std::shared_ptr<aio::Context> &context,
        const Target &target
) {
    std::shared_ptr<zero::async::promise::Promise<std::vector<aio::net::Address>>> promise;

    switch (target.index()) {
        case 0: {
            auto address = std::get<HostAddress>(target);

            promise = aio::net::dns::lookupIP(context, address.hostname)->then(
                    [=](nonstd::span<const std::variant<std::array<std::byte, 4>, std::array<std::byte, 16>>> ips) {
                        std::vector<aio::net::Address> addresses;

                        std::transform(
                                ips.begin(),
                                ips.end(),
                                std::back_inserter(addresses),
                                [=](const auto &ip) -> aio::net::Address {
                                    if (ip.index() == 0)
                                        return aio::net::IPv4Address{address.port, std::get<0>(ip)};

                                    return aio::net::IPv6Address{address.port, std::get<1>(ip)};
                                }
                        );

                        return addresses;
                    }
            );

            break;
        }

        case 1: {
            auto address = std::get<aio::net::IPv4Address>(target);

            promise = zero::async::promise::resolve<std::vector<aio::net::Address>>(
                    std::vector<aio::net::Address>{aio::net::IPv4Address{address.port, address.ip}}
            );

            break;
        }

        case 2: {
            auto address = std::get<aio::net::IPv6Address>(target);

            promise = zero::async::promise::resolve<std::vector<aio::net::Address>>(
                    std::vector<aio::net::Address>{aio::net::IPv6Address{address.port, address.ip}}
            );

            break;
        }
    }

    return promise;
}

std::shared_ptr<zero::async::promise::Promise<void>> proxyUDP(
        const std::shared_ptr<aio::Context> &context,
        const zero::ptr::RefPtr<aio::net::stream::IBuffer> &local
) {
    return readTarget(local)->then([=](const Target &target) {
        LOG_INFO("UDP proxy: %s", stringify(target).c_str());

        return local->readExactly(4)->then([=](nonstd::span<const std::byte> data) {
            return local->readExactly(ntohl(*(uint32_t *) data.data()));
        })->then([=](nonstd::span<const std::byte> data) {
            return resolve(
                    context,
                    target
            )->then([
                            =,
                            payload = std::vector<std::byte>{data.begin(), data.end()}
                    ](nonstd::span<const aio::net::Address> addresses) {
                const aio::net::Address &address = addresses.front();

                zero::ptr::RefPtr<aio::net::dgram::Socket> remote = aio::net::dgram::bind(
                        context,
                        address.index() == 0 ? "0.0.0.0" : "::",
                        0
                );

                if (!remote)
                    return zero::async::promise::reject<void>({-1, "bind failed"});

                return remote->writeTo(payload, address)->then([=]() {
                    return zero::async::promise::all(
                            zero::async::promise::loop<void>([=](const auto &loop) {
                                readTarget(local)->then([=](const Target &target) {
                                    LOG_INFO("UDP proxy: %s", stringify(target).c_str());

                                    local->readExactly(4)->then([=](nonstd::span<const std::byte> data) {
                                        return local->readExactly(ntohl(*(uint32_t *) data.data()));
                                    })->then([=](nonstd::span<const std::byte> data) {
                                        return resolve(
                                                context,
                                                target
                                        )->then([
                                                        =,
                                                        payload = std::vector<std::byte>{data.begin(), data.end()}
                                                ](nonstd::span<const aio::net::Address> addresses) {
                                            return remote->writeTo(payload, addresses.front());
                                        });
                                    });
                                })->then([=]() {
                                    P_CONTINUE(loop);
                                }, [=](const zero::async::promise::Reason &reason) {
                                    P_BREAK_E(loop, reason);
                                });
                            }),
                            zero::async::promise::loop<void>([=](const auto &loop) {
                                remote->readFrom(10240)->then(
                                        [=](nonstd::span<const std::byte> data, const aio::net::Address &from) {
                                            if (from.index() == 0)
                                                writeTarget(local, std::get<aio::net::IPv4Address>(from));
                                            else
                                                writeTarget(local, std::get<aio::net::IPv6Address>(from));

                                            auto length = htonl((uint32_t) payload.size());

                                            local->submit({(const std::byte *) &length, sizeof(length)});
                                            local->submit(payload);

                                            return local->drain();
                                        }
                                )->then([=]() {
                                    P_CONTINUE(loop);
                                }, [=](const zero::async::promise::Reason &reason) {
                                    P_BREAK_E(loop, reason);
                                });
                            })
                    );
                });
            });
        });
    });
}

std::shared_ptr<zero::async::promise::Promise<void>> proxyTCP(
        const std::shared_ptr<aio::Context> &context,
        const zero::ptr::RefPtr<aio::net::stream::IBuffer> &local
) {
    return readTarget(local)->then([=](const Target &target) {
        LOG_INFO("TCP proxy: %s", stringify(target).c_str());

        return resolve(context, target)->then([=](nonstd::span<const aio::net::Address> addresses) {
            return aio::net::stream::connect(
                    context,
                    addresses
            )->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &remote) {
                auto response = {std::byte{0}};

                return local->write(response)->then([=] {
                    return aio::tunnel(local, remote);
                })->finally([=]() {
                    remote->close();
                });
            }, [=](const zero::async::promise::Reason &reason) {
                auto response = {std::byte{1}};

                return local->write(response)->then([=]() {
                    return zero::async::promise::reject<void>(reason);
                });
            });
        });
    });
}

int main(int argc, char **argv) {
    INIT_CONSOLE_LOG(zero::INFO_LEVEL);

    zero::Cmdline cmdline;

    cmdline.add<std::string>("ip", "listen ip");
    cmdline.add<unsigned short>("port", "listen port");

    cmdline.add<std::filesystem::path>("ca", "CA cert path");
    cmdline.add<std::filesystem::path>("cert", "cert path");
    cmdline.add<std::filesystem::path>("key", "private key path");

    cmdline.parse(argc, argv);

    auto ip = cmdline.get<std::string>("ip");
    auto port = cmdline.get<unsigned short>("port");

    std::shared_ptr<aio::Context> context = aio::newContext();

    if (!context)
        return -1;

    aio::net::ssl::Config config = {};

    config.ca = cmdline.get<std::filesystem::path>("ca");
    config.cert = cmdline.get<std::filesystem::path>("cert");
    config.privateKey = cmdline.get<std::filesystem::path>("key");
    config.server = true;

    std::shared_ptr<aio::net::ssl::Context> ctx = aio::net::ssl::newContext(config);

    if (!ctx)
        return -1;

    zero::ptr::RefPtr<aio::net::ssl::stream::Listener> listener = aio::net::ssl::stream::listen(
            context,
            ip,
            port,
            ctx
    );

    if (!listener)
        return -1;

    zero::async::promise::loop<void>([=](const auto &loop) {
        listener->accept()->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
            buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
                auto type = std::to_integer<int>(data[0]);

                if (type == 0)
                    return proxyTCP(context, buffer);

                return proxyUDP(context, buffer);
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

    return 0;
}