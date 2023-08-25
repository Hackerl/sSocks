#include "common.h"
#include <zero/os/net.h>

const char *Category::name() const noexcept {
    return "sSocks";
}

std::string Category::message(int value) const {
    std::string msg;

    switch (value) {
        case UNSUPPORTED_VERSION:
            msg = "unsupported version";
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

const std::error_category &category() {
    static Category instance;
    return instance;
}

std::error_code make_error_code(Error e) {
    return {static_cast<int>(e), category()};
}

zero::async::coroutine::Task<Target, std::error_code>
readTarget(std::shared_ptr<asyncio::net::stream::IBuffer> buffer) {
    std::byte type[1];
    auto res = co_await buffer->readExactly(type);

    if (!res)
        co_return tl::unexpected(res.error());

    std::byte port[2];
    res = co_await buffer->readExactly(port);

    if (!res)
        co_return tl::unexpected(res.error());

    tl::expected<Target, std::error_code> result = tl::unexpected(
            make_error_code(std::errc::address_family_not_supported)
    );

    switch (std::to_integer<size_t>(type[0])) {
        case 0: {
            auto hostname = co_await buffer->readLine();

            if (!hostname) {
                result = tl::unexpected(hostname.error());
                break;
            }

            result = HostAddress{ntohs(*(uint16_t *) port), *hostname};
            break;
        }

        case 1: {
            std::array<std::byte, 4> ip = {};
            res = co_await buffer->readExactly(ip);

            if (!res) {
                result = tl::unexpected(res.error());
                break;
            }

            result = asyncio::net::IPv4Address{ntohs(*(uint16_t *) port), ip};
            break;
        }

        case 2: {
            std::array<std::byte, 16> ip = {};
            res = co_await buffer->readExactly(ip);

            if (!res) {
                result = tl::unexpected(res.error());
                break;
            }

            result = asyncio::net::IPv6Address{ntohs(*(uint16_t *) port), ip};
            break;
        }
    }

    co_return result;
}

zero::async::coroutine::Task<void, std::error_code>
writeTarget(std::shared_ptr<asyncio::net::stream::IBuffer> buffer, Target target) {
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
            auto address = std::get<asyncio::net::IPv4Address>(target);
            auto port = htons(address.port);
            auto type = {std::byte{1}};

            buffer->submit(type);
            buffer->submit({(const std::byte *) &port, sizeof(port)});
            buffer->submit(address.ip);

            break;
        }

        case 2: {
            auto address = std::get<asyncio::net::IPv6Address>(target);
            auto port = htons(address.port);
            auto type = {std::byte{2}};

            buffer->submit(type);
            buffer->submit({(const std::byte *) &port, sizeof(port)});
            buffer->submit(address.ip);

            break;
        }
    }

    co_return co_await buffer->drain();
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
            result = std::get<asyncio::net::IPv4Address>(target).string();
            break;
        }

        case 2: {
            result = std::get<asyncio::net::IPv6Address>(target).string();
            break;
        }
    }

    return result;
}