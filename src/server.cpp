#include "common.h"
#include <asyncio/binary.h>
#include <asyncio/signal.h>
#include <asyncio/net/tls.h>
#include <asyncio/net/dgram.h>
#include <asyncio/net/stream.h>
#include <zero/log.h>
#include <zero/cmdline.h>

asyncio::task::Task<void, std::error_code>
UDPToRemote(const std::uint64_t id, asyncio::IReader &local, asyncio::net::UDPSocket &remote) {
    while (true) {
        const auto target = co_await readTarget(local);
        CO_EXPECT(target);

        const auto length = co_await asyncio::binary::readBE<std::uint32_t>(local);
        CO_EXPECT(length);

        LOG_DEBUG("[{}] send {} bytes to {}", id, *length, *target);

        std::vector<std::byte> payload(*length);
        CO_EXPECT(co_await local.readExactly(payload));

        CO_EXPECT(co_await std::visit(
            [&]<typename T>(const T &arg) {
                if constexpr (std::is_same_v<T, HostAddress>) {
                    return remote.writeTo(payload, arg.hostname, arg.port);
                }
                else {
                    return remote.writeTo(payload, arg);
                }
            },
            *target
        ));
    }
}

asyncio::task::Task<void, std::error_code>
UDPToClient(const std::uint64_t id, asyncio::net::UDPSocket &remote, asyncio::IWriter &local) {
    while (true) {
        std::array<std::byte, 65535> data; // NOLINT(*-pro-type-member-init)

        const auto result = co_await remote.readFrom(data);
        CO_EXPECT(result);

        const auto &[n, from] = *result;
        LOG_DEBUG("[{}] receive {} bytes from {}", id, n, from);

        if (std::holds_alternative<asyncio::net::IPv4Address>(from)) {
            CO_EXPECT(co_await writeTarget(local, std::get<asyncio::net::IPv4Address>(from)));
        }
        else {
            CO_EXPECT(co_await writeTarget(local, std::get<asyncio::net::IPv6Address>(from)));
        }

        CO_EXPECT(co_await asyncio::binary::writeBE(local, static_cast<std::uint32_t>(n)));
        CO_EXPECT(co_await local.writeAll({data.data(), n}));
    }
}

asyncio::task::Task<void, std::error_code>
proxyTCP(const std::uint64_t id, asyncio::net::tls::TLS<asyncio::net::TCPStream> local) {
    auto target = co_await readTarget(local);
    CO_EXPECT(target);

    LOG_INFO("[{}] target: {}", id, *target);

    auto remote = co_await std::visit(
        []<typename T>(T arg) {
            if constexpr (std::is_same_v<T, HostAddress>) {
                return asyncio::net::TCPStream::connect(std::move(arg.hostname), arg.port);
            }
            else {
                return asyncio::net::TCPStream::connect(std::move(arg));
            }
        },
        *std::move(target)
    );

    if (!remote) {
        CO_EXPECT(co_await asyncio::binary::writeBE(local, std::to_underlying(ProxyStatus::FAIL)));
        co_return std::unexpected(remote.error());
    }

    CO_EXPECT(co_await asyncio::binary::writeBE(local, std::to_underlying(ProxyStatus::SUCCESS)));

    co_return co_await copyBidirectional(local, *remote).andThen([&] {
        return local.close();
    });
}

asyncio::task::Task<void, std::error_code>
handle(const std::uint64_t id, asyncio::net::tls::TLS<asyncio::net::TCPStream> tls) {
    const auto type = co_await asyncio::binary::readBE<std::int32_t>(tls);
    CO_EXPECT(type);

    if (static_cast<ProxyType>(*type) == ProxyType::TCP)
        co_return co_await proxyTCP(id, std::move(tls));

    auto remote = asyncio::net::UDPSocket::make();
    CO_EXPECT(remote);

    co_return co_await race(
        UDPToRemote(id, tls, *remote),
        UDPToClient(id, *remote, tls)
    ).andThen([&] {
        return tls.close();
    });
}

asyncio::task::Task<void, std::error_code>
serve(asyncio::net::TCPListener listener, const asyncio::net::tls::Context context) {
    while (true) {
        auto stream = co_await listener.accept();
        CO_EXPECT(stream);

        const auto localAddress = stream->localAddress();
        const auto remoteAddress = stream->remoteAddress();

        if (!localAddress || !remoteAddress)
            continue;

        static std::uint64_t counter;
        const auto id = counter++;

        LOG_INFO("[{}] session: fd={} address={} client={}", id, stream->fd(), *localAddress, *remoteAddress);

        asyncio::net::tls::accept(*std::move(stream), context)
            .andThen([=](asyncio::net::tls::TLS<asyncio::net::TCPStream> tls) {
                return handle(id, std::move(tls));
            })
            .future().fail([=](const std::error_code &ec) {
                LOG_ERROR("[{}] unhandled error: {} ({})", id, ec.message(), ec);
            });
    }
}

asyncio::task::Task<void, std::error_code> asyncMain(const int argc, char *argv[]) {
    INIT_CONSOLE_LOG(zero::LogLevel::INFO_LEVEL);

    zero::Cmdline cmdline;

    cmdline.add<std::string>("ip", "listen ip");
    cmdline.add<unsigned short>("port", "listen port");

    cmdline.add<std::filesystem::path>("ca", "CA cert path");
    cmdline.add<std::filesystem::path>("cert", "cert path");
    cmdline.add<std::filesystem::path>("key", "private key path");

    cmdline.parse(argc, argv);

    const auto ip = cmdline.get<std::string>("ip");
    const auto port = cmdline.get<unsigned short>("port");
    const auto caFile = cmdline.get<std::filesystem::path>("ca");
    const auto certFile = cmdline.get<std::filesystem::path>("cert");
    const auto keyFile = cmdline.get<std::filesystem::path>("key");

    auto ca = asyncio::net::tls::Certificate::loadFile(caFile);
    CO_EXPECT(ca);

    auto cert = asyncio::net::tls::Certificate::loadFile(certFile);
    CO_EXPECT(cert);

    auto key = asyncio::net::tls::PrivateKey::loadFile(keyFile);
    CO_EXPECT(key);

    const asyncio::net::tls::ServerConfig config = {
        .rootCAs = {*std::move(ca)},
        .certKeyPairs = {{*std::move(cert), *std::move(key)}}
    };

    auto context = config.build();
    CO_EXPECT(context);

    auto listener = asyncio::net::TCPListener::listen(ip, port);
    CO_EXPECT(listener);

    auto signal = asyncio::Signal::make();
    CO_EXPECT(signal);

    co_return co_await race(
        signal->on(SIGINT).transform([](const int) {
        }),
        serve(*std::move(listener), *std::move(context))
    );
}
