#include "tools/admin/user_ops.hpp"
#include "core/crypto.hpp"
#include "core/server.hpp"
#include "core/shortid.hpp"
#include "core/user_store.hpp"
#include "registry/tool_registry.hpp"
#include <json.hpp>
#include <spawn.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <regex>
#include <stdexcept>
#include <string>

extern char** environ;

using json = nlohmann::json;

namespace {

bool is_email_ish(const std::string& s) {
    static const std::regex re(R"(^[^\s@]+@[^\s@]+\.[^\s@]+$)");
    return std::regex_match(s, re);
}

void atomic_write_excl(const std::string& path, const std::string& data) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) throw std::runtime_error(std::string("open ") + path + ": " + std::strerror(errno));
    std::size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) { ::close(fd); ::unlink(path.c_str()); throw std::runtime_error("write"); }
        off += n;
    }
    ::fsync(fd);
    ::close(fd);
}

void atomic_replace(const std::string& path, const std::string& data) {
    std::string tmp = path + ".tmp." + std::to_string(::getpid());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) throw std::runtime_error("open tmp");
    std::size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) { ::close(fd); ::unlink(tmp.c_str()); throw std::runtime_error("write"); }
        off += n;
    }
    ::fsync(fd); ::close(fd);
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        throw std::runtime_error("rename");
    }
}

int spawn_helper(const std::string& helper_path, const std::string& sub,
                 const std::string& shortid) {
    char* argv_c[] = {
        const_cast<char*>(helper_path.c_str()),
        const_cast<char*>(sub.c_str()),
        const_cast<char*>(shortid.c_str()),
        nullptr
    };
    char path_env[] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    char* env_c[] = {path_env, nullptr};

    pid_t pid;
    int rc = posix_spawn(&pid, helper_path.c_str(), nullptr, nullptr, argv_c, env_c);
    if (rc != 0) return -1;
    int st;
    if (::waitpid(pid, &st, 0) < 0) return -1;
    if (!WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}

json read_user_doc(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) throw std::runtime_error("no user record at " + path);
    json doc;
    try { in >> doc; } catch (...) { throw std::runtime_error("malformed user record"); }
    if (!doc.is_object()) throw std::runtime_error("user record is not an object");
    return doc;
}

json public_view(const json& doc) {
    return {
        {"user_id", doc.value("user_id", "")},
        {"os_username", doc.value("os_username", "")},
        {"name", doc.value("name", "")},
        {"email", doc.value("email", "")},
        {"is_admin", doc.value("is_admin", false)},
        {"created_at", doc.value("created_at", int64_t{0})},
        {"rotated_at", doc.value("rotated_at", int64_t{0})}
    };
}

}

void register_user_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("user_create", {
        "",
        "Create a new MCP user. Generates shortid + bearer token, writes the user "
        "record, and provisions the OS account via the privileged helper. The "
        "returned token is shown once and cannot be retrieved later. Admin-only.",
        {"name", "email"}, {"is_admin"},
        [](const RequestContext& ctx, const json& args) -> json {
            if (!ctx.is_admin) throw std::runtime_error("admin only");

            auto name  = args.at("name").get<std::string>();
            auto email = args.at("email").get<std::string>();
            bool is_admin = args.value("is_admin", false);
            if (name.empty()) throw std::runtime_error("name is required");
            if (!is_email_ish(email)) throw std::runtime_error("email is not well-formed");

            const auto& cfg = Server::config();
            if (cfg.global_token_salt.empty())
                throw std::runtime_error("server missing global_token_salt");

            auto shortid = mcp::make_shortid();
            auto token   = mcp::make_token();
            auto hash    = crypto::sha256_salted_hex(cfg.global_token_salt, token);

            json record = {
                {"user_id", shortid},
                {"os_username", "mcp_user_" + shortid},
                {"name", name},
                {"email", email},
                {"is_admin", is_admin},
                {"token_hash", hash},
                {"created_at", static_cast<int64_t>(std::time(nullptr))}
            };

            std::string user_path = cfg.users_dir + "/" + shortid + ".json";
            atomic_write_excl(user_path, record.dump(2) + "\n");

            int rc = spawn_helper(cfg.helper_path, "useradd", shortid);
            // 14 = OS account already exists; treat as idempotent.
            bool os_provisioned = (rc == 0 || rc == 14);

            Server::users().reload();

            return {
                {"user_id", shortid},
                {"os_username", "mcp_user_" + shortid},
                {"name", name},
                {"email", email},
                {"is_admin", is_admin},
                {"token", token},
                {"os_provisioned", os_provisioned},
                {"helper_exit", rc}
            };
        }
    });

    reg.register_tool("user_update", {
        "",
        "Update a user's mutable details (name, email, is_admin). At least one "
        "optional field must be provided. Token is not affected — use auth rotate "
        "for that. Admin-only.",
        {"shortid"}, {"name", "email", "is_admin"},
        [](const RequestContext& ctx, const json& args) -> json {
            if (!ctx.is_admin) throw std::runtime_error("admin only");

            auto shortid = args.at("shortid").get<std::string>();
            if (!mcp::valid_shortid(shortid)) throw std::runtime_error("invalid shortid");

            const auto& cfg = Server::config();
            std::string user_path = cfg.users_dir + "/" + shortid + ".json";
            auto doc = read_user_doc(user_path);

            bool changed = false;
            if (args.contains("name")) {
                auto v = args.at("name").get<std::string>();
                if (v.empty()) throw std::runtime_error("name cannot be empty");
                doc["name"] = v;
                changed = true;
            }
            if (args.contains("email")) {
                auto v = args.at("email").get<std::string>();
                if (!is_email_ish(v)) throw std::runtime_error("email is not well-formed");
                doc["email"] = v;
                changed = true;
            }
            if (args.contains("is_admin")) {
                doc["is_admin"] = args.at("is_admin").get<bool>();
                changed = true;
            }
            if (!changed) throw std::runtime_error("no updatable field provided");

            doc["updated_at"] = static_cast<int64_t>(std::time(nullptr));
            atomic_replace(user_path, doc.dump(2) + "\n");
            Server::users().reload();

            return public_view(doc);
        }
    });

    reg.register_tool("user_delete", {
        "",
        "Delete a user record and remove the corresponding OS account via the "
        "privileged helper. Idempotent on the OS side. Refuses to delete the "
        "caller's own account. Admin-only.",
        {"shortid"}, {},
        [](const RequestContext& ctx, const json& args) -> json {
            if (!ctx.is_admin) throw std::runtime_error("admin only");

            auto shortid = args.at("shortid").get<std::string>();
            if (!mcp::valid_shortid(shortid)) throw std::runtime_error("invalid shortid");
            if (shortid == ctx.user_id)
                throw std::runtime_error("refusing to delete the calling user");

            const auto& cfg = Server::config();
            std::string user_path = cfg.users_dir + "/" + shortid + ".json";

            bool record_existed = (::access(user_path.c_str(), F_OK) == 0);
            if (record_existed && ::unlink(user_path.c_str()) != 0)
                throw std::runtime_error(std::string("unlink: ") + std::strerror(errno));

            int rc = spawn_helper(cfg.helper_path, "userdel", shortid);

            Server::users().reload();

            return {
                {"user_id", shortid},
                {"record_deleted", record_existed},
                {"os_account_removed", rc == 0},
                {"helper_exit", rc}
            };
        }
    });
}
