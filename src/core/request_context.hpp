#pragma once
#include <string>

struct RequestContext {
    std::string user_id;        // shortid; "admin" for the install admin token
    std::string os_username;    // mcp_user_<shortid>; "mcp_user_mcpadmin" for the install admin token
    bool is_admin = false;
    std::string session_id;     // populated in Phase 5 (MCP sessions)
    std::string bearer_hash;    // hex sha256(global_salt || bearer)
    std::string client_ip;
};
