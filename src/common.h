#ifndef SOCKS_COMMON_H
#define SOCKS_COMMON_H

#include <aio/net/stream.h>

enum Error {
    INVALID_VERSION = -2000,
    INVALID_ADDRESS,
    INVALID_REQUEST,
    INVALID_USER,
    INVALID_PACKET,
    UNSUPPORTED_METHOD,
    UNSUPPORTED_AUTH_METHOD,
    HANDSHAKE_FAILED,
    ADDRESS_RESOLVE_ERROR,
    AUTH_FAILED,
    PROXY_FAILED
};

struct HostAddress {
    unsigned short port;
    std::string hostname;
};

using Target = std::variant<HostAddress, aio::net::IPv4Address, aio::net::IPv6Address>;

std::string stringify(const Target &target);

std::shared_ptr<zero::async::promise::Promise<Target>>
readTarget(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer);

void writeTarget(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer, const Target &target);

#endif //SOCKS_COMMON_H
