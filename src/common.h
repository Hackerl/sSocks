#ifndef SOCKS_COMMON_H
#define SOCKS_COMMON_H

#include <asyncio/binary.h>
#include <asyncio/net/net.h>

enum class ProxyType : std::int32_t {
    TCP,
    UDP
};

enum class ProxyStatus : std::int32_t {
    SUCCESS,
    FAIL
};

enum class AddressType : std::int32_t {
    HOSTNAME,
    IPV4,
    IPV6
};

struct HostAddress {
    unsigned short port;
    std::string hostname;
};

using Target = std::variant<HostAddress, asyncio::net::IPv4Address, asyncio::net::IPv6Address>;

DEFINE_ERROR_CODE(
    ReadTargetError,
    "readTarget",
    UNSUPPORTED_ADDRESS_TYPE, "unsupported address type"
)

DECLARE_ERROR_CODE(ReadTargetError)

asyncio::task::Task<Target, std::error_code> readTarget(asyncio::Trait<asyncio::IReader> auto &reader) {
    const auto type = co_await asyncio::binary::readBE<std::int32_t>(reader);
    CO_EXPECT(type);

    const auto port = co_await asyncio::binary::readBE<unsigned short>(reader);
    CO_EXPECT(port);

    switch (static_cast<AddressType>(*type)) {
    case AddressType::HOSTNAME: {
        const auto length = co_await asyncio::binary::readBE<std::size_t>(reader);
        CO_EXPECT(length);

        std::string hostname;
        hostname.resize(*length);

        CO_EXPECT(co_await std::invoke(
            &asyncio::IReader::readExactly,
            reader,
            std::as_writable_bytes(std::span{hostname})
        ));

        co_return HostAddress{*port, std::move(hostname)};
    }

    case AddressType::IPV4: {
        std::array<std::byte, 4> ip = {};
        CO_EXPECT(co_await std::invoke(&asyncio::IReader::readExactly, reader, ip));
        co_return asyncio::net::IPv4Address{*port, ip};
    }

    case AddressType::IPV6: {
        std::array<std::byte, 16> ip = {};
        CO_EXPECT(co_await std::invoke(&asyncio::IReader::readExactly, reader, ip));
        co_return asyncio::net::IPv6Address{*port, ip};
    }

    default:
        co_return std::unexpected(ReadTargetError::UNSUPPORTED_ADDRESS_TYPE);
    }
}

asyncio::task::Task<void, std::error_code> writeTarget(asyncio::Trait<asyncio::IWriter> auto &writer, Target target) {
    co_return co_await std::visit(
        [&]<typename T>(T arg) -> asyncio::task::Task<void, std::error_code> {
            if constexpr (std::is_same_v<T, HostAddress>) {
                const auto &[port, hostname] = arg;

                CO_EXPECT(co_await asyncio::binary::writeBE(writer, std::to_underlying(AddressType::HOSTNAME)));
                CO_EXPECT(co_await asyncio::binary::writeBE(writer, port));
                CO_EXPECT(co_await asyncio::binary::writeBE(writer, hostname.length()));
                CO_EXPECT(co_await writer.writeAll(std::as_bytes(std::span{hostname})));
            }
            else if constexpr (std::is_same_v<T, asyncio::net::IPv4Address>) {
                const auto [port, ip] = arg;

                CO_EXPECT(co_await asyncio::binary::writeBE(writer, std::to_underlying(AddressType::IPV4)));
                CO_EXPECT(co_await asyncio::binary::writeBE(writer, port));
                CO_EXPECT(co_await writer.writeAll(ip));
            }
            else {
                const auto &[port, ip, zone] = arg;

                CO_EXPECT(co_await asyncio::binary::writeBE(writer, std::to_underlying(AddressType::IPV6)));
                CO_EXPECT(co_await asyncio::binary::writeBE(writer, port));
                CO_EXPECT(co_await writer.writeAll(ip));
            }

            co_return {};
        },
        std::move(target)
    );
}

template<typename Char>
struct fmt::formatter<HostAddress, Char> {
    template<typename ParseContext>
    static constexpr auto parse(ParseContext &ctx) {
        return ctx.begin();
    }

    template<typename FmtContext>
    static auto format(const HostAddress &address, FmtContext &ctx) {
        return fmt::format_to(ctx.out(), "{}:{}", address.hostname, address.port);
    }
};

#endif //SOCKS_COMMON_H
