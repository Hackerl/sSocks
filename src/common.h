#ifndef SOCKS_COMMON_H
#define SOCKS_COMMON_H

#include <asyncio/net/stream.h>

enum Error {
    UNSUPPORTED_VERSION,
    UNSUPPORTED_COMMAND,
    UNSUPPORTED_AUTH_VERSION,
    UNSUPPORTED_AUTH_METHOD,
    UNSUPPORTED_ADDRESS_TYPE,
    AUTH_FAILED,
    FORBIDDEN_ADDRESS,
    INVALID_UDP_PACKET,
    NO_DNS_RECORD
};

class ErrorCategory final : public std::error_category {
public:
    [[nodiscard]] const char *name() const noexcept override;
    [[nodiscard]] std::string message(int value) const override;
};

const std::error_category &errorCategory();
std::error_code make_error_code(Error e);

struct HostAddress {
    unsigned short port;
    std::string hostname;
};

using Target = std::variant<HostAddress, asyncio::net::IPv4Address, asyncio::net::IPv6Address>;

zero::async::coroutine::Task<Target, std::error_code> readTarget(asyncio::IBufReader &reader);

zero::async::coroutine::Task<void, std::error_code>
writeTarget(asyncio::IBufWriter &writer, Target target);

template<>
struct std::is_error_code_enum<Error> : std::true_type {

};

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
