#include "common.h"
#include <asyncio/binary.h>
#include <asyncio/ev/signal.h>
#include <asyncio/net/ssl.h>
#include <asyncio/net/dgram.h>
#include <asyncio/net/dns.h>
#include <asyncio/event_loop.h>
#include <zero/log.h>
#include <zero/defer.h>
#include <zero/cmdline.h>
#include <csignal>

zero::async::coroutine::Task<std::vector<asyncio::net::Address>, std::error_code> resolve(Target target) {
    switch (target.index()) {
        case 0: {
            const auto &[port, hostname] = std::get<HostAddress>(target);
            const auto result = CO_TRY(co_await asyncio::net::dns::lookupIP(hostname));

            const auto v = *result | std::views::transform([=](const auto &ip) -> asyncio::net::Address {
                if (ip.index() == 0)
                    return asyncio::net::IPv4Address{port, std::get<0>(ip)};

                return asyncio::net::IPv6Address{port, std::get<1>(ip)};
            });

            co_return std::vector<asyncio::net::Address>{v.begin(), v.end()};
        }

        case 1: {
            const auto [port, ip] = std::get<asyncio::net::IPv4Address>(target);
            co_return std::vector<asyncio::net::Address>{asyncio::net::IPv4Address{port, ip}};
        }

        case 2: {
            const auto &[port, ip, zone] = std::get<asyncio::net::IPv6Address>(target);
            co_return std::vector<asyncio::net::Address>{asyncio::net::IPv6Address{port, ip}};
        }

        default:
            std::abort();
    }
}

zero::async::coroutine::Task<void, std::error_code>
UDPToRemote(
    const std::shared_ptr<asyncio::net::stream::IBuffer> local,
    const std::shared_ptr<asyncio::net::dgram::Socket> remote
) {
    const auto clientAddress = local->remoteAddress();

    while (true) {
        const auto target = CO_TRY(co_await readTarget(*local));
        const auto length = CO_TRY(co_await asyncio::binary::readBE<std::uint32_t>(*local));

        std::vector<std::byte> payload(*length);
        CO_TRY(co_await local->readExactly(payload));

        const auto addresses = CO_TRY(co_await resolve(*target));

        if (addresses->empty())
            co_return tl::unexpected(NO_DNS_RECORD);

        const auto &address = addresses->front();
        LOG_DEBUG("UDP packet: {} = {} => {}", *clientAddress, payload.size(),*target);
        CO_TRY(co_await remote->writeTo(payload, address));
    }
}

zero::async::coroutine::Task<void, std::error_code>
UDPToClient(
    const std::shared_ptr<asyncio::net::dgram::Socket> remote,
    const std::shared_ptr<asyncio::net::stream::IBuffer> local
) {
    const auto clientAddress = local->remoteAddress();

    while (true) {
        std::byte data[10240];
        const auto result = CO_TRY(co_await remote->readFrom(data));
        const auto &[n, from] = *result;

        LOG_DEBUG("UDP packet: {} <= {} = {}", *clientAddress, n, from);

        if (from.index() == 0) {
            CO_TRY(co_await writeTarget(*local, std::get<asyncio::net::IPv4Address>(from)));
        }
        else {
            CO_TRY(co_await writeTarget(*local, std::get<asyncio::net::IPv6Address>(from)));
        }

        CO_TRY(co_await asyncio::binary::writeBE(*local, static_cast<std::uint32_t>(n)));
        CO_TRY(co_await local->writeAll({data, n}));
        CO_TRY(co_await local->flush());
    }
}

zero::async::coroutine::Task<void, std::error_code> proxyUDP(asyncio::net::ssl::stream::Buffer local) {
    const auto clientAddress = CO_TRY(local.remoteAddress());
    LOG_INFO("UDP proxy: {}", *clientAddress);

    const auto target = CO_TRY(co_await readTarget(local));
    const auto length = CO_TRY(co_await asyncio::binary::readBE<std::uint32_t>(local));

    std::vector<std::byte> payload(*length);
    CO_TRY(co_await local.readExactly(payload));

    const auto addresses = CO_TRY(co_await resolve(*target));

    if (addresses->empty())
        co_return tl::unexpected(NO_DNS_RECORD);

    const auto &address = addresses->front();
    auto remote = CO_TRY(asyncio::net::dgram::bind(address.index() == 0 ? "0.0.0.0" : "::", 0));

    LOG_DEBUG("UDP packet: {} = {} => {}", *clientAddress, payload.size(), *target);
    DEFER(LOG_INFO("UDP proxy finished: {}", *clientAddress));

    CO_TRY(co_await remote->writeTo(payload, address));

    const auto localBuffer = std::make_shared<asyncio::net::ssl::stream::Buffer>(std::move(local));
    const auto remoteSocket = std::make_shared<asyncio::net::dgram::Socket>(std::move(*remote));

    co_return co_await race(UDPToRemote(localBuffer, remoteSocket), UDPToClient(remoteSocket, localBuffer));
}

zero::async::coroutine::Task<void, std::error_code> proxyTCP(asyncio::net::ssl::stream::Buffer local) {
    const auto clientAddress = CO_TRY(local.remoteAddress());
    const auto target = CO_TRY(co_await readTarget(local));

    LOG_INFO("TCP proxy: {} <==> {}", *clientAddress, *target);

    const auto addresses = CO_TRY(co_await resolve(*target));

    if (addresses->empty())
        co_return tl::unexpected(NO_DNS_RECORD);

    auto remote = std::move(co_await asyncio::net::stream::connect(*addresses));

    if (!remote) {
        LOG_ERROR("connect to remote failed[{}]", remote.error().message());

        constexpr std::array status = {std::byte{1}};
        CO_TRY(co_await local.writeAll(status));
        co_return tl::expected<void, std::error_code>{};
    }

    LOG_INFO("TCP tunnel: {} <==> {}", *clientAddress, *target);

    constexpr std::array status = {std::byte{0}};
    CO_TRY(co_await local.writeAll(status));

    co_return co_await race(copy(local, *remote), copy(*remote, local));
}

zero::async::coroutine::Task<void, std::error_code> handle(asyncio::net::ssl::stream::Buffer buffer) {
    std::byte type[1];
    CO_TRY(co_await buffer.readExactly(type));

    if (std::to_integer<int>(type[0]) == 0)
        co_return co_await proxyTCP(std::move(buffer));

    co_return co_await proxyUDP(std::move(buffer));
}

zero::async::coroutine::Task<void, std::error_code> serve(asyncio::net::ssl::stream::Listener listener) {
    while (true) {
        auto buffer = CO_TRY(std::move(co_await listener.accept()));

        const auto local = CO_TRY(buffer->localAddress());
        const auto remote = CO_TRY(buffer->remoteAddress());

        LOG_INFO("new connection: {} <==> {}", *local, *remote);

        handle(std::move(*buffer)).promise().then(
            [=] {
                LOG_INFO("{} <==> {} disconnect", *local, *remote);
            },
            [=](const std::error_code&ec) {
                LOG_INFO("{} <==> {} disconnect[{}]", *local, *remote, ec.message());
            }
        );
    }
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

    const auto ip = cmdline.get<std::string>("ip");
    const auto port = cmdline.get<unsigned short>("port");
    const auto ca = cmdline.get<std::filesystem::path>("ca");
    const auto cert = cmdline.get<std::filesystem::path>("cert");
    const auto privateKey = cmdline.get<std::filesystem::path>("key");

    asyncio::run([&]() -> zero::async::coroutine::Task<void> {
        const auto context = asyncio::net::ssl::newContext(
            {
                .ca = ca,
                .cert = cert,
                .privateKey = privateKey,
                .server = true
            }
        );

        if (!context) {
            LOG_ERROR("create ssl context failed[{}]", context.error().message());
            co_return;
        }

        auto listener = asyncio::net::ssl::stream::listen(*context, ip, port);

        if (!listener) {
            LOG_ERROR("listen failed[{}]", listener.error().message());
            co_return;
        }

        auto signal = asyncio::ev::makeSignal(SIGINT);

        if (!signal) {
            LOG_ERROR("make signal failed[{}]", signal.error().message());
            co_return;
        }

        co_await race(signal->on(), serve(std::move(*listener)));
    });

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}