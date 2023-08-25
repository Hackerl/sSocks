#include "common.h"
#include <asyncio/ev/signal.h>
#include <asyncio/net/ssl.h>
#include <asyncio/net/dgram.h>
#include <asyncio/net/dns.h>
#include <asyncio/event_loop.h>
#include <zero/log.h>
#include <zero/cmdline.h>
#include <csignal>

zero::async::coroutine::Task<std::vector<asyncio::net::Address>, std::error_code> resolve(Target target) {
    tl::expected<std::vector<asyncio::net::Address>, std::error_code> result;

    switch (target.index()) {
        case 0: {
            auto address = std::get<HostAddress>(target);
            auto res = co_await asyncio::net::dns::lookupIP(address.hostname);

            if (!res) {
                result = tl::unexpected(res.error());
                break;
            }

            std::transform(
                    res->begin(),
                    res->end(),
                    std::back_inserter(*result),
                    [=](const auto &ip) -> asyncio::net::Address {
                        if (ip.index() == 0)
                            return asyncio::net::IPv4Address{address.port, std::get<0>(ip)};

                        return asyncio::net::IPv6Address{address.port, std::get<1>(ip)};
                    }
            );

            break;
        }

        case 1: {
            auto address = std::get<asyncio::net::IPv4Address>(target);
            result->emplace_back(asyncio::net::IPv4Address{address.port, address.ip});
            break;
        }

        case 2: {
            auto address = std::get<asyncio::net::IPv6Address>(target);
            result->emplace_back(asyncio::net::IPv6Address{address.port, address.ip});
            break;
        }
    }

    co_return result;
}

zero::async::coroutine::Task<void, std::error_code> UDPToRemote(
        std::shared_ptr<asyncio::net::stream::IBuffer> local,
        std::shared_ptr<asyncio::net::dgram::Socket> remote
) {
    auto clientAddress = local->remoteAddress();

    if (!clientAddress)
        co_return tl::unexpected(clientAddress.error());

    tl::expected<void, std::error_code> result;

    while (true) {
        auto target = co_await readTarget(local);

        if (!target) {
            result = tl::unexpected(target.error());
            break;
        }

        std::byte length[4];
        auto res = co_await local->readExactly(length);

        if (!res) {
            result = tl::unexpected(res.error());
            break;
        }

        std::vector<std::byte> payload(ntohl(*(uint32_t *) length));
        res = co_await local->readExactly(payload);

        if (!res) {
            result = tl::unexpected(res.error());
            break;
        }

        auto addresses = co_await resolve(*target);

        if (!addresses) {
            result = tl::unexpected(addresses.error());
            break;
        }

        if (addresses->empty()) {
            result = tl::unexpected<std::error_code>(Error::NO_DNS_RECORD);
            break;
        }

        auto address = addresses->front();

        LOG_DEBUG(
                "UDP packet[%s = %zu => %s]",
                stringify(*clientAddress).c_str(),
                payload.size(),
                stringify(*target).c_str()
        );

        res = co_await remote->writeTo(payload, address);

        if (!res) {
            result = tl::unexpected(res.error());
            break;
        }
    }

    co_return result;
}

zero::async::coroutine::Task<void, std::error_code> UDPToClient(
        std::shared_ptr<asyncio::net::dgram::Socket> remote,
        std::shared_ptr<asyncio::net::stream::IBuffer> local
) {
    auto clientAddress = local->remoteAddress();

    if (!clientAddress)
        co_return tl::unexpected(clientAddress.error());

    tl::expected<void, std::error_code> result;

    while (true) {
        std::byte data[10240];
        auto res = co_await remote->readFrom(data);

        if (!res) {
            result = tl::unexpected(res.error());
            break;
        }

        auto &[n, from] = *res;

        LOG_DEBUG(
                "UDP packet[%s <= %zu = %s]",
                stringify(*clientAddress).c_str(),
                n,
                stringify(from).c_str()
        );

        auto r = from.index() == 0 ?
                 (co_await writeTarget(local, std::get<asyncio::net::IPv4Address>(from))) :
                 (co_await writeTarget(local, std::get<asyncio::net::IPv6Address>(from)));

        if (!r) {
            result = tl::unexpected(r.error());
            break;
        }

        auto length = htonl((uint32_t) n);

        local->submit({(const std::byte *) &length, sizeof(length)});
        local->submit({data, n});

        r = co_await local->drain();

        if (!r) {
            result = tl::unexpected(r.error());
            break;
        }
    }

    co_return result;
}

zero::async::coroutine::Task<void> proxyUDP(std::shared_ptr<asyncio::net::stream::IBuffer> local) {
    auto clientAddress = local->remoteAddress();

    if (!clientAddress) {
        LOG_ERROR("get remote address failed[%s]", clientAddress.error().message().c_str());
        co_return;
    }

    LOG_INFO("UDP proxy[%s]", stringify(*clientAddress).c_str());

    auto target = co_await readTarget(local);

    if (!target) {
        LOG_ERROR("read target failed[%s]", target.error().message().c_str());
        co_return;
    }

    std::byte length[4];
    auto result = co_await local->readExactly(length);

    if (!result) {
        LOG_ERROR("read packet length failed[%s]", result.error().message().c_str());
        co_return;
    }

    std::vector<std::byte> payload(ntohl(*(uint32_t *) length));
    result = co_await local->readExactly(payload);

    if (!result) {
        LOG_ERROR("read packet failed[%s]", result.error().message().c_str());
        co_return;
    }

    auto addresses = co_await resolve(*target);

    if (!addresses) {
        LOG_ERROR("resolve target failed[%s]", addresses.error().message().c_str());
        co_return;
    }

    if (addresses->empty()) {
        LOG_WARNING("no dns record found");
        co_return;
    }

    auto address = addresses->front();
    auto remote = asyncio::net::dgram::bind(address.index() == 0 ? "0.0.0.0" : "::", 0)
            .transform([](asyncio::net::dgram::Socket &&socket) {
                return std::make_shared<asyncio::net::dgram::Socket>(std::move(socket));
            });

    if (!remote) {
        LOG_ERROR("bind failed[%s]", remote.error().message().c_str());
        co_return;
    }

    LOG_DEBUG(
            "UDP packet[%s = %zu => %s]",
            stringify(*clientAddress).c_str(),
            payload.size(),
            stringify(*target).c_str()
    );

    result = co_await remote.value()->writeTo(payload, address);

    if (!result) {
        LOG_ERROR("write to remote failed[%s]", result.error().message().c_str());
        co_return;
    }

    auto res = co_await zero::async::coroutine::race(UDPToRemote(local, *remote), UDPToClient(*remote, local));

    if (!res) {
        LOG_ERROR("UDP proxy failed[%s]", res.error().message().c_str());
        co_return;
    }

    LOG_INFO("UDP proxy finished[%s]", stringify(*clientAddress).c_str());
}

zero::async::coroutine::Task<void> proxyTCP(std::shared_ptr<asyncio::net::stream::IBuffer> local) {
    auto clientAddress = local->remoteAddress();

    if (!clientAddress) {
        LOG_ERROR("get remote address failed[%s]", clientAddress.error().message().c_str());
        co_return;
    }

    auto target = co_await readTarget(local);

    if (!target) {
        LOG_ERROR("read target failed[%s]", target.error().message().c_str());
        co_return;
    }

    LOG_INFO("TCP proxy[%s <==> %s]", stringify(*clientAddress).c_str(), stringify(*target).c_str());

    auto addresses = co_await resolve(*target);

    if (!addresses) {
        LOG_ERROR("resolve target failed[%s]", addresses.error().message().c_str());
        co_return;
    }

    if (addresses->empty()) {
        LOG_WARNING("no dns record found");
        co_return;
    }

    auto remote = std::move(co_await asyncio::net::stream::connect(*addresses)).transform(
            [](asyncio::net::stream::Buffer &&buffer) {
                return std::make_shared<asyncio::net::stream::Buffer>(std::move(buffer));
            }
    );

    if (!remote) {
        LOG_ERROR("connect to remote failed[%s]", remote.error().message().c_str());

        auto status = {std::byte{1}};
        auto res = co_await local->write(status);

        if (!res) {
            LOG_ERROR("write status code failed[%s]", res.error().message().c_str());
            co_return;
        }

        co_return;
    }

    LOG_INFO(
            "TCP tunnel[%s <==> %s]",
            stringify(*clientAddress).c_str(),
            stringify(*target).c_str()
    );

    auto status = {std::byte{0}};
    auto res = co_await local->write(status);

    if (!res) {
        LOG_ERROR("write status code failed[%s]", res.error().message().c_str());
        co_return;
    }

    co_await zero::async::coroutine::race(asyncio::copy(local, *remote), asyncio::copy(*remote, local));
}

zero::async::coroutine::Task<void> handle(std::shared_ptr<asyncio::net::stream::IBuffer> buffer) {
    std::byte type[1];
    auto result = co_await buffer->readExactly(type);

    if (!result) {
        LOG_ERROR("read proxy type failed[%s]", result.error().message().c_str());
        co_return;
    }

    if (std::to_integer<int>(type[0]) == 0) {
        co_await proxyTCP(std::move(buffer));
        co_return;
    }

    co_await proxyUDP(std::move(buffer));
}

zero::async::coroutine::Task<void, std::error_code> serve(asyncio::net::ssl::stream::Listener listener) {
    tl::expected<void, std::error_code> result;

    while (true) {
        auto buffer = std::move(co_await listener.accept());

        if (!buffer) {
            result = tl::unexpected(buffer.error());
            break;
        }

        handle(std::make_shared<asyncio::net::ssl::stream::Buffer>(std::move(*buffer)));
    }

    co_return result;
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

#if __unix__ || __APPLE__
    signal(SIGPIPE, SIG_IGN);
#endif

    auto ip = cmdline.get<std::string>("ip");
    auto port = cmdline.get<unsigned short>("port");
    auto ca = cmdline.get<std::filesystem::path>("ca");
    auto cert = cmdline.get<std::filesystem::path>("cert");
    auto privateKey = cmdline.get<std::filesystem::path>("key");

    asyncio::run([&]() -> zero::async::coroutine::Task<void> {
        auto context = asyncio::net::ssl::newContext(
                {
                        .ca = ca,
                        .cert = cert,
                        .privateKey = privateKey,
                        .server = true
                }
        );

        if (!context) {
            LOG_ERROR("create ssl context failed[%s]", context.error().message().c_str());
            co_return;
        }

        auto listener = asyncio::net::ssl::stream::listen(*context, ip, port);

        if (!listener) {
            LOG_ERROR("listen failed[%s]", listener.error().message().c_str());
            co_return;
        }

        auto signal = asyncio::ev::makeSignal(SIGINT);

        if (!signal) {
            LOG_ERROR("make signal failed[%s]", signal.error().message().c_str());
            co_return;
        }

        co_await zero::async::coroutine::race(signal->on(), serve(std::move(*listener)));
    });

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}