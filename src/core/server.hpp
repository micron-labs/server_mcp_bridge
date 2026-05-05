#pragma once
#include "core/config.hpp"
#include "core/context.hpp"
#include "core/cron_store.hpp"
#include "core/grants.hpp"
#include "core/mcp_router.hpp"
#include "core/rate_limiter.hpp"
#include "core/session.hpp"
#include "core/user_store.hpp"

class Server {
public:
    explicit Server(const Config& config, std::string config_path);
    void start();

    // Shared state accessible by tools
    static Config& config();
    static Context& context();
    static GrantManager& grants();
    static UserStore& users();
    static CronStore& crons();

private:
    Config config_;
    std::string config_path_;
    UserStore users_;
    RateLimiter rate_limiter_;
    Context context_;
    GrantManager grants_;
    CronStore crons_;
    SessionStore sessions_;
    McpRouter router_;

    static Config* s_config_;
    static Context* s_context_;
    static GrantManager* s_grants_;
    static UserStore* s_users_;
    static CronStore* s_crons_;
};
