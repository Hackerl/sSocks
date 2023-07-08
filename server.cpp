#include "common.h"
#include <aio/net/ssl.h>
#include <aio/net/dgram.h>
#include <aio/net/dns.h>
#include <zero/log.h>
#include <zero/cmdline.h>

#ifdef __unix__
#include <csignal>
#endif

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

    return promise->fail(
            PF_RETHROW(
                    ADDRESS_RESOLVE_ERROR,
                    zero::strings::format("resolve target %s failed", stringify(target).c_str())
            )
    );
}

std::shared_ptr<zero::async::promise::Promise<void>> proxyUDP(
        const std::shared_ptr<aio::Context> &context,
        const zero::ptr::RefPtr<aio::net::stream::IBuffer> &local
) {
    std::optional<aio::net::Address> clientAddress = local->remoteAddress();

    if (!clientAddress)
        return zero::async::promise::reject<void>(
                {aio::IO_ERROR, zero::strings::format("failed to get remote address[%s]", aio::lastError().c_str())}
        );

    LOG_INFO("UDP proxy: client[%s]", stringify(*clientAddress).c_str());

    return readTarget(local)->then([=](const Target &target) {
        return local->readExactly(4)->then([=](nonstd::span<const std::byte> data) {
            return local->readExactly(ntohl(*(uint32_t *) data.data()));
        })->then([=](nonstd::span<const std::byte> data) {
            return resolve(context, target)->then([
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
                    return zero::async::promise::reject<void>(
                            {
                                    aio::IO_ERROR,
                                    zero::strings::format("create datagram socket failed[%s]", aio::lastError().c_str())
                            }
                    );

                LOG_DEBUG(
                        "UDP packet[%llu]: %s ==> %s",
                        payload.size(),
                        stringify(*clientAddress).c_str(),
                        stringify(target).c_str()
                );

                return remote->writeTo(payload, address)->then([=]() {
                    return zero::async::promise::all(
                            zero::async::promise::doWhile([=]() {
                                return readTarget(local)->then([=](const Target &target) {
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
                                            LOG_DEBUG(
                                                    "UDP packet[%llu]: %s ==> %s",
                                                    payload.size(),
                                                    stringify(*clientAddress).c_str(),
                                                    stringify(target).c_str()
                                            );

                                            return remote->writeTo(payload, addresses.front());
                                        });
                                    });
                                });
                            }),
                            zero::async::promise::doWhile([=]() {
                                return remote->readFrom(10240)->then(
                                        [=](nonstd::span<const std::byte> data, const aio::net::Address &from) {
                                            LOG_DEBUG(
                                                    "UDP packet[%llu]: %s <== %s",
                                                    data.size(),
                                                    stringify(*clientAddress).c_str(),
                                                    stringify(from).c_str()
                                            );

                                            if (from.index() == 0)
                                                writeTarget(local, std::get<aio::net::IPv4Address>(from));
                                            else
                                                writeTarget(local, std::get<aio::net::IPv6Address>(from));

                                            auto length = htonl((uint32_t) data.size());

                                            local->submit({(const std::byte *) &length, sizeof(length)});
                                            local->submit(data);

                                            return local->drain();
                                        }
                                );
                            })
                    );
                })->finally([=]() {
                    remote->close();
                });
            });
        });
    })->finally([=]() {
        LOG_INFO("UDP proxy finished: client[%s]", stringify(*clientAddress).c_str());
    });
}

std::shared_ptr<zero::async::promise::Promise<void>> proxyTCP(
        const std::shared_ptr<aio::Context> &context,
        const zero::ptr::RefPtr<aio::net::stream::IBuffer> &local
) {
    std::optional<aio::net::Address> clientAddress = local->remoteAddress();

    if (!clientAddress)
        return zero::async::promise::reject<void>(
                {aio::IO_ERROR, zero::strings::format("failed to get remote address[%s]", aio::lastError().c_str())}
        );

    LOG_INFO("TCP proxy: client[%s]", stringify(*clientAddress).c_str());

    return readTarget(local)->then([=](const Target &target) {
        LOG_INFO(
                "TCP proxy request: client[%s] target[%s]",
                stringify(*clientAddress).c_str(),
                stringify(target).c_str()
        );

        return resolve(context, target)->then([=](nonstd::span<const aio::net::Address> addresses) {
            return aio::net::stream::connect(
                    context,
                    addresses
            )->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &remote) {
                LOG_INFO(
                        "TCP tunnel: client[%s] target[%s]",
                        stringify(*clientAddress).c_str(),
                        stringify(target).c_str()
                );

                auto response = {std::byte{0}};

                return local->write(response)->then([=] {
                    return aio::tunnel(local, remote);
                })->finally([=]() {
                    remote->close();
                });
            }, [=](const zero::async::promise::Reason &reason) {
                auto response = {std::byte{1}};

                return local->write(response)->then([=]() {
                    return nonstd::make_unexpected(reason);
                });
            });
        });
    })->finally([=]() {
        LOG_INFO("TCP proxy finished: client[%s]", stringify(*clientAddress).c_str());
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

    zero::async::promise::doWhile([=]() {
        return listener->accept()->then([=](const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
            buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
                auto type = std::to_integer<int>(data[0]);

                if (type == 0)
                    return proxyTCP(context, buffer);

                return proxyUDP(context, buffer);
            })->fail([](const zero::async::promise::Reason &reason) {
                std::vector<std::string> messages = {
                        zero::strings::format("code[%d] msg[%s]", reason.code, reason.message.c_str())
                };

                for (auto p = reason.previous; p; p = p->previous)
                    messages.push_back(zero::strings::format("code[%d] msg[%s]", p->code, p->message.c_str()));

                LOG_ERROR(
                        "%s",
                        zero::strings::join(messages, " << ").c_str()
                );
            })->finally([=]() {
                buffer->close();
            });
        });
    })->fail([](const zero::async::promise::Reason &reason) {
        LOG_ERROR("code[%d] msg[%s]", reason.code, reason.message.c_str());
    })->finally([=]() {
        context->loopBreak();
    });

    context->dispatch();

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}