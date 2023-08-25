#ifndef SOCKS_COMMON_H
#define SOCKS_COMMON_H

#include <asyncio/net/stream.h>

enum Error {
    UNSUPPORTED_VERSION,
    UNSUPPORTED_AUTH_VERSION,
    UNSUPPORTED_AUTH_METHOD,
    UNSUPPORTED_ADDRESS_TYPE,
    AUTH_FAILED,
    FORBIDDEN_ADDRESS,
    INVALID_UDP_PACKET,
    NO_DNS_RECORD
};

class Category : public std::error_category {
public:
    [[nodiscard]] const char *name() const noexcept override;
    [[nodiscard]] std::string message(int value) const override;
};

const std::error_category &category();
std::error_code make_error_code(Error e);

namespace std {
    template<>
    struct is_error_code_enum<Error> : public true_type {

    };
}

struct HostAddress {
    unsigned short port;
    std::string hostname;
};

using Target = std::variant<HostAddress, asyncio::net::IPv4Address, asyncio::net::IPv6Address>;

std::string stringify(const Target &target);

zero::async::coroutine::Task<Target, std::error_code> readTarget(std::shared_ptr<asyncio::net::stream::IBuffer> buffer);

zero::async::coroutine::Task<void, std::error_code>
writeTarget(std::shared_ptr<asyncio::net::stream::IBuffer> buffer, Target target);

#endif //SOCKS_COMMON_H
