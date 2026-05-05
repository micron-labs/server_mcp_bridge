#pragma once
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

struct CronJob {
    std::string job_id;        // 16 lowercase hex chars
    std::string user_id;       // owner shortid
    std::string os_username;   // mcp_user_<shortid>
    std::string schedule;      // 5-field cron expression
    std::string command;       // shell command line, run via `bash -c`
    std::string description;
    std::string context_id;
    int64_t created_at = 0;
    int64_t updated_at = 0;
};

// Persistent store of all cron jobs across all users. Source of truth lives in
// `<state_dir>/crons.json`; per-user copies of {job_id, schedule, command,
// description, context_id} are written into each user's runtime state dir
// separately (see runtime_sync) so the cron-runner running as that user can
// read them.
class CronStore {
public:
    explicit CronStore(std::string state_dir);

    void load();

    CronJob add(const std::string& user_id,
                const std::string& os_username,
                const std::string& schedule,
                const std::string& command,
                const std::string& description,
                const std::string& context_id);

    // Mutates only the fields whose optional is engaged. Throws std::runtime_error
    // if the job doesn't exist or `os_username` doesn't match the owner.
    CronJob update(const std::string& job_id,
                   const std::string& os_username,
                   const std::optional<std::string>& schedule,
                   const std::optional<std::string>& command,
                   const std::optional<std::string>& description,
                   const std::optional<std::string>& context_id);

    // Throws if not found or os_username mismatch. Returns the removed job.
    CronJob remove(const std::string& job_id, const std::string& os_username);

    std::vector<CronJob> list_for_user(const std::string& os_username) const;

    std::optional<CronJob> find(const std::string& job_id) const;

    std::size_t size() const;

    // Validation helpers (free-standing for testing).
    static bool valid_jobid(const std::string& s);
    static bool valid_schedule(const std::string& s);

private:
    void persist_locked();
    void load_locked();

    std::string state_dir_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, CronJob> jobs_;
};
