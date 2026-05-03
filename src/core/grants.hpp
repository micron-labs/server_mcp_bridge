#pragma once
#include "core/grant_template.hpp"
#include "core/request_context.hpp"
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

struct Grant {
    std::string grantid;       // 16 hex chars
    std::string shortid;       // 8 chars (Crockford-base32)
    std::string template_name;
    json captured_args;
    int64_t expires_at = 0;    // unix seconds
};

class GrantManager {
public:
    struct Config {
        std::string state_dir;          // /var/lib/mcp_bridge/state
        std::string sudoers_dir;        // /etc/sudoers.d
        std::string helper_path;        // /usr/lib/mcp_bridge/mcp_bridge-priv
        std::vector<GrantTemplate> templates;
        std::chrono::seconds sweep_interval{30};
    };

    explicit GrantManager(Config config);
    ~GrantManager();

    Grant request_grant(const RequestContext& ctx,
                        const std::string& shortid,
                        const std::string& template_name,
                        const json& captured_args,
                        std::chrono::seconds ttl);

    // Idempotent. Removes the sudoers drop-in via the helper, then erases the
    // grant from in-memory state and grants.json.
    void revoke_grant(const std::string& grantid);

    // Sweep expired grants; called by the sweeper thread.
    void sweep_expired();

    // Reconcile on-disk state with /etc/sudoers.d at startup. Anything in
    // sudoers_dir matching mcp_grant_* but not in state is revoked; entries in
    // state past their expiry are revoked too.
    void reconcile_at_startup();

    void start_sweeper();
    void stop_sweeper();

    std::size_t size() const;

private:
    void persist_state_locked();
    void load_state_locked();

    // Render the spec, drop it into the state dir as `grant_<grantid>.spec`,
    // then invoke the helper `install-grant <grantid>` which moves it into
    // /etc/sudoers.d. Returns helper exit code; non-zero means the spec file
    // is left behind for forensics.
    int spawn_helper(const std::vector<std::string>& argv, std::string& stderr_out) const;
    int install_grant_via_helper(const Grant& g, const std::string& spec, std::string& err) const;
    int revoke_grant_via_helper(const std::string& grantid, std::string& err) const;

    void log_audit(const std::string& event, const RequestContext& ctx,
                   const std::string& grantid, const std::string& detail) const;

    Config config_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Grant> grants_;

    std::thread sweep_thread_;
    std::condition_variable sweep_cv_;
    std::mutex sweep_mutex_;
    bool stopping_ = false;
};
