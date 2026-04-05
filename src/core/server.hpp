#pragma once
#include "core/config.hpp"
#include "core/rate_limiter.hpp"
#include "core/context.hpp"
#include <memory>

class Server {
public:
    explicit Server(const Config& config);
    void start();

    // Shared state accessible by tools
    static Config& config();
    static Context& context();

private:
    Config config_;
    RateLimiter rate_limiter_;
    Context context_;

    static Config* s_config_;
    static Context* s_context_;
};
