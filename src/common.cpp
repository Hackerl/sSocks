#include "common.h"
#include <zero/try.h>
#include <zero/os/net.h>
#include <asyncio/binary.h>

const char *ErrorCategory::name() const noexcept {
    return "sSocks";
}

std::string ErrorCategory::message(const int value) const {
    std::string msg;

    switch (value) {
        case UNSUPPORTED_VERSION:
            msg = "unsupported version";
            break;

        case UNSUPPORTED_COMMAND:
            msg = "unsupported command";
            break;

        case UNSUPPORTED_AUTH_VERSION:
            msg = "unsupported auth version";
            break;

        case UNSUPPORTED_AUTH_METHOD:
            msg = "unsupported auth method";
            break;

        case UNSUPPORTED_ADDRESS_TYPE:
            msg = "unsupported address type";
            break;

        case AUTH_FAILED:
            msg = "auth failed";
            break;

        case FORBIDDEN_ADDRESS:
            msg = "forbidden address";
            break;

        case INVALID_UDP_PACKET:
            msg = "invalid UDP packet";
            break;

        case NO_DNS_RECORD:
            msg = "no dns record";
            break;

        default:
            msg = "unknown";
            break;
    }

    return msg;
}

const std::error_category &errorCategory() {
    static ErrorCategory instance;
    return instance;
}

std::error_code make_error_code(const Error e) {
    return {static_cast<int>(e), errorCategory()};
}

zero::async::coroutine::Task<Target, std::error_code> readTarget(asyncio::IBufReader &reader) {
    std::byte type[1];
    CO_TRY(co_await reader.readExactly(type));

    const auto port = CO_TRY(co_await asyncio::binary::readBE<unsigned short>(reader));

    switch (std::to_integer<std::size_t>(type[0])) {
        case 0: {
            auto hostname = CO_TRY(co_await reader.readLine());
            co_return HostAddress{*port, std::move(*hostname)};
        }

        case 1: {
            std::array<std::byte, 4> ip = {};
            CO_TRY(co_await reader.readExactly(ip));
            co_return asyncio::net::IPv4Address{*port, ip};
        }

        case 2: {
            std::array<std::byte, 16> ip = {};
            CO_TRY(co_await reader.readExactly(ip));
            co_return asyncio::net::IPv6Address{*port, ip};
        }

        default:
            co_return tl::unexpected(make_error_code(std::errc::address_family_not_supported));
    }
}

zero::async::coroutine::Task<void, std::error_code> writeTarget(asyncio::IBufWriter &writer, Target target) {
    switch (target.index()) {
        case 0: {
            const auto &[port, hostname] = std::get<HostAddress>(target);
            constexpr std::array type = {std::byte{0}};

            CO_TRY(co_await writer.writeAll(type));
            CO_TRY(co_await asyncio::binary::writeBE(writer, port));
            CO_TRY(co_await writer.writeAll(std::as_bytes(std::span{hostname})));
            CO_TRY(co_await writer.writeAll(std::as_bytes(std::span{std::string_view{"\r\n"}})));

            break;
        }

        case 1: {
            const auto [port, ip] = std::get<asyncio::net::IPv4Address>(target);
            constexpr std::array type = {std::byte{1}};

            CO_TRY(co_await writer.writeAll(type));
            CO_TRY(co_await asyncio::binary::writeBE(writer, port));
            CO_TRY(co_await writer.writeAll(ip));

            break;
        }

        case 2: {
            const auto &[port, ip, zone] = std::get<asyncio::net::IPv6Address>(target);
            constexpr std::array type = {std::byte{2}};

            CO_TRY(co_await writer.writeAll(type));
            CO_TRY(co_await asyncio::binary::writeBE(writer, port));
            CO_TRY(co_await writer.writeAll(ip));

            break;
        }

        default:
            std::abort();
    }

    co_return co_await writer.flush();
}
