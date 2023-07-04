#include "common.h"
#include <cstring>
#include <zero/os/net.h>

void writeTarget(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer, const Target &target) {
    switch (target.index()) {
        case 0: {
            auto address = std::get<HostAddress>(target);
            auto port = htons(address.port);
            auto type = {std::byte{0}};

            buffer->submit(type);
            buffer->submit({(const std::byte *) &port, sizeof(port)});
            buffer->writeLine(address.hostname);

            break;
        }

        case 1: {
            auto address = std::get<aio::net::IPv4Address>(target);
            auto port = htons(address.port);
            auto type = {std::byte{1}};

            buffer->submit(type);
            buffer->submit({(const std::byte *) &port, sizeof(port)});
            buffer->submit(address.ip);

            break;
        }

        case 2: {
            auto address = std::get<aio::net::IPv6Address>(target);
            auto port = htons(address.port);
            auto type = {std::byte{2}};

            buffer->submit(type);
            buffer->submit({(const std::byte *) &port, sizeof(port)});
            buffer->submit(address.ip);

            break;
        }
    }
}

std::shared_ptr<zero::async::promise::Promise<Target>>
readTarget(const zero::ptr::RefPtr<aio::net::stream::IBuffer> &buffer) {
    return buffer->readExactly(1)->then([=](nonstd::span<const std::byte> data) {
        std::shared_ptr<zero::async::promise::Promise<Target>> promise;

        switch (std::to_integer<size_t>(data[0])) {
            case 0: {
                promise = buffer->readExactly(2)->then([=](nonstd::span<const std::byte> data) {
                    auto port = ntohs(*(uint16_t *) data.data());
                    return buffer->readLine()->then([=](const std::string &hostname) -> Target {
                        return HostAddress{port, hostname};
                    });
                });

                break;
            }

            case 1: {
                promise = buffer->readExactly(2)->then([=](nonstd::span<const std::byte> data) {
                    auto port = ntohs(*(uint16_t *) data.data());
                    return buffer->readExactly(4)->then([=](nonstd::span<const std::byte, 4> data) -> Target {
                        aio::net::IPv4Address address = {};

                        address.port = port;
                        memcpy(address.ip.data(), data.data(), 4);

                        return address;
                    });
                });

                break;
            }

            case 2: {
                promise = buffer->readExactly(2)->then([=](nonstd::span<const std::byte> data) {
                    auto port = ntohs(*(uint16_t *) data.data());
                    return buffer->readExactly(16)->then([=](nonstd::span<const std::byte, 16> data) -> Target {
                        aio::net::IPv6Address address = {};

                        address.port = port;
                        memcpy(address.ip.data(), data.data(), 16);

                        return address;
                    });
                });

                break;
            }

            default:
                promise = zero::async::promise::reject<Target>({-1, "unsupported target type"});
                break;
        }

        return promise;
    });
}

std::string stringify(const Target &target) {
    std::string result;

    switch (target.index()) {
        case 0: {
            auto address = std::get<HostAddress>(target);
            result = address.hostname + ":" + std::to_string(address.port);
            break;
        }

        case 1: {
            auto address = std::get<aio::net::IPv4Address>(target);
            result = zero::os::net::stringify(address.ip) + ":" + std::to_string(address.port);
            break;
        }

        case 2: {
            auto address = std::get<aio::net::IPv6Address>(target);
            result = zero::os::net::stringify(address.ip) + ":" + std::to_string(address.port);
            break;
        }
    }

    return result;
}