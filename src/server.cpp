#include "common.h"
#include <asyncio/binary.h>
#include <asyncio/signal.h>
#include <asyncio/net/tls.h>
#include <asyncio/net/dgram.h>
#include <asyncio/net/stream.h>
#include <zero/log.h>
#include <zero/cmdline.h>
#include <zero/formatter.h>

asyncio::task::Task<void>
UDPToRemote(const std::uint64_t id, asyncio::IReader &local, asyncio::net::UDPSocket &remote) {
    while (true) {
        auto target = co_await readTarget(local);
        const auto length = zero::error::guard(co_await asyncio::binary::readBE<std::uint32_t>(local));

        Z_LOG_DEBUG("[{}] Send {} bytes to {}", id, length, target);

        std::vector<std::byte> payload(length);
        zero::error::guard(co_await local.readExactly(payload));

        zero::error::guard(co_await std::visit(
            [&]<typename T>(T arg) {
                if constexpr (std::is_same_v<T, HostAddress>) {
                    return remote.writeTo(payload, std::move(arg.hostname), arg.port);
                }
                else {
                    return remote.writeTo(payload, std::move(arg));
                }
            },
            std::move(target)
        ));
    }
}

asyncio::task::Task<void>
UDPToClient(const std::uint64_t id, asyncio::net::UDPSocket &remote, asyncio::IWriter &local) {
    while (true) {
        std::array<std::byte, 65535> data; // NOLINT(*-pro-type-member-init)

        const auto &[n, from] = zero::error::guard(co_await remote.readFrom(data));
        Z_LOG_DEBUG("[{}] Receive {} bytes from {}", id, n, from);

        if (std::holds_alternative<asyncio::net::IPv4Address>(from))
            co_await writeTarget(local, std::get<asyncio::net::IPv4Address>(from));
        else
            co_await writeTarget(local, std::get<asyncio::net::IPv6Address>(from));

        zero::error::guard(co_await asyncio::binary::writeBE(local, static_cast<std::uint32_t>(n)));
        zero::error::guard(co_await local.writeAll({data.data(), n}));
    }
}

asyncio::task::Task<void>
proxyTCP(const std::uint64_t id, asyncio::net::tls::TLS<asyncio::net::TCPStream> local) {
    auto target = co_await readTarget(local);
    Z_LOG_INFO("[{}] Target: {}", id, target);

    auto remote = co_await std::visit(
        []<typename T>(T arg) {
            if constexpr (std::is_same_v<T, HostAddress>) {
                return asyncio::net::TCPStream::connect(std::move(arg.hostname), arg.port);
            }
            else {
                return asyncio::net::TCPStream::connect(std::move(arg));
            }
        },
        std::move(target)
    );

    if (!remote) {
        zero::error::guard(co_await asyncio::binary::writeBE(local, std::to_underlying(ProxyStatus::FAIL)));
        throw zero::error::SystemError{remote.error()};
    }

    zero::error::guard(co_await asyncio::binary::writeBE(local, std::to_underlying(ProxyStatus::SUCCESS)));
    zero::error::guard(co_await asyncio::net::copyBidirectional(local, *remote));
}

asyncio::task::Task<void>
handle(const std::uint64_t id, asyncio::net::TCPStream stream, asyncio::net::tls::Context context) {
    Z_LOG_INFO(
        "[{}] Session: fd={} address={} client={}",
        id,
        stream.fd(),
        zero::error::guard(stream.localAddress()),
        zero::error::guard(stream.remoteAddress())
    );

    auto tls = zero::error::guard(co_await asyncio::net::tls::accept(std::move(stream), std::move(context)));

    if (const auto type = zero::error::guard(co_await asyncio::binary::readBE<std::int32_t>(tls));
        static_cast<ProxyType>(type) == ProxyType::TCP) {
        co_await proxyTCP(id, std::move(tls));
        co_return;
    }

    auto remote = zero::error::guard(asyncio::net::UDPSocket::bind("0.0.0.0", 0));

    co_await race(
        UDPToRemote(id, tls, remote),
        UDPToClient(id, remote, tls)
    );

    zero::error::guard(co_await tls.close());
}

asyncio::task::Task<void> serve(asyncio::net::TCPListener listener, const asyncio::net::tls::Context context) {
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

        auto task = handle(id, *std::move(stream), context);
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

    cmdline.add<std::string>("ip", "Server listen IP address");
    cmdline.add<std::uint16_t>("port", "Server listen port");

    cmdline.add<std::filesystem::path>("ca", "CA certificate file path");
    cmdline.add<std::filesystem::path>("cert", "Server certificate file path");
    cmdline.add<std::filesystem::path>("key", "Private key file path");

    cmdline.parse(argc, argv);

    const auto ip = cmdline.get<std::string>("ip");
    const auto port = cmdline.get<std::uint16_t>("port");
    const auto caFile = cmdline.get<std::filesystem::path>("ca");
    const auto certFile = cmdline.get<std::filesystem::path>("cert");
    const auto keyFile = cmdline.get<std::filesystem::path>("key");

    auto ca = zero::error::guard(co_await asyncio::net::tls::Certificate::loadFile(caFile));
    auto cert = zero::error::guard(co_await asyncio::net::tls::Certificate::loadFile(certFile));
    auto key = zero::error::guard(co_await asyncio::net::tls::PrivateKey::loadFile(keyFile));

    auto context = zero::error::guard(
        asyncio::net::tls::ServerConfig{}
        .rootCAs({std::move(ca)})
        .certKeyPairs({{std::move(cert), std::move(key)}})
        .build()
    );

    auto listener = zero::error::guard(asyncio::net::TCPListener::listen(ip, port));
    auto signal = asyncio::Signal::make();

    co_await race(
        serve(std::move(listener), std::move(context)),
        asyncio::task::spawn([&]() -> asyncio::task::Task<void> {
            zero::error::guard(co_await signal.on(SIGINT));
        })
    );
}
