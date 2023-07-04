#ifndef SOCKS_COMMON_H
#define SOCKS_COMMON_H

#include <aio/net/stream.h>

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
