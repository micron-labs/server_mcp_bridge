# MCP Bridge

A lightweight C++ API bridge that exposes server management functionality to external systems such as MCP servers or AI agents. Designed for VPS and self-hosted servers (no cPanel required).

Provides programmatic management of files, databases, networking, web servers, processes, command execution, and sandboxed code execution through a secure HTTP interface.

---

## Overview

The system runs as a single compiled binary on your server and provides:

- Native MCP / JSON-RPC 2.0 transport with `Mcp-Session-Id` session binding
- Per-OS-user multi-tenancy (each end user gets a `mcp_user_<shortid>` POSIX account)
- Setuid helper for time-limited sudoers grants (admin-only)
- Tool-based execution model (67 tools across 9 modules)
- Context tracking
- Logging via systemd journal + rotating file + `LOG_AUTHPRIV` audit trail
- Per-user rate limiting
- Linux first-class (systemd unit, setuid helper, sudoers grants, `.deb`); Windows builds the daemon binary only (no privilege model)

```
MCP client (Claude Desktop, Claude Code, Cursor, LangChain, curl, …)
  |
  |  JSON-RPC 2.0 over HTTP   (POST /   +   GET / for SSE notifications)
  v
MCP Bridge daemon  (this binary — the MCP server)
  |
  |  Runs as user `mcp`; privileged ops via setuid helper + scoped sudoers drop-ins
  v
Server resources (files, databases, services, processes, sandbox)
```

---

## Directory Structure

```
mcp_bridge/
  CMakeLists.txt              # Build system (mcp_bridge + mcp_bridge-priv)
  etc/mcp_bridge/
    mcp.json.template         # Postinst-materialized config template
  installer/
    install.sh                # `curl | bash` installer
    release.md                # Per-release publishing checklist
  debian/                     # Debian packaging (mcp-bridge.service, postinst, …)

  vendor/                     # Header-only dependencies
    httplib.h                 # cpp-httplib (HTTP + SSE)
    json.hpp                  # nlohmann/json
    spdlog/                   # spdlog (logging)

  src/
    main.cpp                  # argv[1] dispatch: daemon | auth …
    core/
      server.cpp/hpp          # MCP transport — POST JSON-RPC, GET SSE
      jsonrpc.cpp/hpp         # JSON-RPC 2.0 envelope
      mcp_router.cpp/hpp      # initialize / tools/list / tools/call …
      session.cpp/hpp         # Mcp-Session-Id issue/validate
      auth.cpp/hpp            # Bearer→user resolution (UserStore + admin fallback)
      user_store.cpp/hpp      # /var/lib/mcp_bridge/users/*.json index
      grants.cpp/hpp          # Sudoers drop-in lifecycle
      grant_template.cpp/hpp  # Template render + spec-shape check
      crypto.cpp/hpp          # SHA-256, hex, constant-time compare
      shortid.cpp/hpp         # 8-char base32 IDs + UUID-v4
      config.cpp/hpp          # JSON config parser
      rate_limiter.cpp/hpp    # Per-user rate limit + GC
      context.cpp/hpp         # Cross-tool persistent K/V store
      request_context.hpp     # Per-request identity threaded into tools
      logger.cpp/hpp          # spdlog initialization
    cli/
      cli_main.cpp/hpp        # `mcp_bridge auth …` dispatcher
      auth_create.cpp         # Create user + write record + SIGHUP
      auth_rotate.cpp         # Rotate token, invalidate sessions
      welcome_banner.cpp/hpp  # /dev/tty connection block
    priv/
      main.c                  # Setuid helper (libc only) — useradd, install/revoke-grant
    registry/
      tool_registry.cpp/hpp   # Tool map, MCP-shaped inputSchema synthesis
      tool_types.hpp          # ToolDef + handler signature
    platform/
      platform.hpp            # Cross-platform shims
      linux/   |   windows/
    tools/
      data/{file_ops,database_ops}            # 12 + 16 tools
      networking/{port_ops,firewall_ops}      #  5 +  5 tools
      hosting/{webserver_ops,process_mgmt}    # 11 +  3 tools
      exec/command_ops                        #  5 tools
      sandbox/sandbox_ops                     #  4 tools
      admin/{grant_ops,user_ops}              #  2 + 3 admin-only tools
```

---

## Requirements

- C++17 compiler (GCC 9+, Clang 10+, or MSVC 2019+)
- CMake 3.20+
- **Optional:** OpenSSL (for HTTPS), MariaDB/MySQL client library, libpq (PostgreSQL)

---

## Build

### Linux (minimal, no database connectors)

```bash
cmake -B build -DENABLE_MYSQL=OFF -DENABLE_POSTGRES=OFF
cmake --build build
```

### Linux (full, with database connectors and HTTPS)

```bash
# Install optional dependencies (Debian/Ubuntu)
sudo apt install libssl-dev libmariadb-dev libpq-dev

cmake -B build -DENABLE_SSL=ON
cmake --build build
```

### Windows (Visual Studio)

```bash
cmake -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `ENABLE_MYSQL` | `ON` | Enable MySQL/MariaDB native connector support |
| `ENABLE_POSTGRES` | `ON` | Enable PostgreSQL native connector support |
| `ENABLE_SSL` | `OFF` | Enable HTTPS via OpenSSL |
| `BUILD_TESTS` | `OFF` | Build test suite |

Database tools work without native connectors by falling back to CLI tools (`mysql`, `psql`, `mysqldump`, `pg_dump`).

---

## Install

### Recommended: one-line installer

```bash
curl -fsSL https://<domain>/install.sh | bash
```

To inspect first:

```bash
curl -fsSL https://<domain>/install.sh | less
```

The installer detects your distro (Ubuntu 22.04/24.04, Debian 12), downloads
the matching `.deb`, verifies a SHA-256 checksum, runs `apt install`, enables
the systemd service, and prints a one-time admin token to `/dev/tty` (so the
token isn't captured in `apt`'s persistent term log).

### Apt repo (second-class path)

If your operator policy forbids `curl | bash`, the same `.deb`s are published
to an apt repo. See `installer/release.md` for the current repo URL.

### Manual

Download the right `.deb` for your distro from the Releases page, plus its
`.deb.sha256` sibling, verify, and `sudo apt install ./mcp-bridge_*.deb`.

---

## Configuration

After install, configuration lives at `/etc/mcp_bridge/mcp.json` (mode 0640,
owner `root:mcp`). The package ships a template at
`/usr/share/mcp_bridge/mcp.json.template`; postinst materializes it on first
install, generating `auth.global_token_salt` and `auth.admin_token_hash` from
a fresh 32-byte token. The plaintext admin token is printed once to `/dev/tty`
during install — save it.

The JSON layout, with defaults:

```jsonc
{
  "server":   { "host": "0.0.0.0", "port": 8080,
                "enable_ssl": false, "ssl_cert": "", "ssl_key": "" },
  "auth":     { "global_token_salt": "<hex>",
                "admin_token_hash":  "<hex>" },
  "paths":    { "users_dir":   "/var/lib/mcp_bridge/users",
                "state_dir":   "/var/lib/mcp_bridge/state",
                "sudoers_dir": "/etc/sudoers.d",
                "helper_path": "/usr/lib/mcp_bridge/mcp_bridge-priv" },
  "security": { "allowed_ips": [], "rate_limit": 60,
                "allowed_root": "/",
                "dangerous_tools_enabled": true,
                "enable_raw_queries": false },
  "mysql":    { "host": "localhost", "port": 3306,
                "root_user": "root", "root_password": "" },
  "postgres": { "host": "localhost", "port": 5432,
                "root_user": "postgres", "root_password": "" },
  "webserver":{ "nginx_config_dir": "/etc/nginx",
                "apache_config_dir": "/etc/apache2",
                "certbot_path": "/usr/bin/certbot" },
  "sandbox":  { "temp_dir": "/tmp/mcp_sandbox",
                "default_timeout": 30, "default_memory_mb": 256,
                "enable_network": false },
  "logging":  { "file": "/var/log/mcp_bridge/server.log",
                "level": "info" },
  "grant_sweep_interval_seconds": 30,
  "sudo_grant_templates": [ /* see Privilege escalation section */ ]
}
```

Send `SIGHUP` (or `systemctl reload mcp-bridge`) after editing user records;
the `/etc/mcp_bridge/mcp.json` file itself is read once at startup.

---

## Provisioning users

The single shared admin token bootstraps the install. Beyond that, each
operator gets their own user record under `/var/lib/mcp_bridge/users/`:

```bash
sudo mcp_bridge auth create --name "Bob" --email "bob@example.com"
# (interactive prompts if --name / --email omitted)

sudo mcp_bridge auth create --admin --non-interactive \
    --name "Alice" --email "alice@example.com"

sudo mcp_bridge auth rotate <shortid>
```

Each user gets:
- An 8-char `shortid` (RFC 4648 base32, lowercase).
- A POSIX account `mcp_user_<shortid>` (no shell, not in the sudo group).
- A 32-byte hex bearer token, printed once on `/dev/tty`. Lost? Rotate.
- A user record JSON file storing only the salted SHA-256 hash of the token.

The daemon picks up new/rotated users on `SIGHUP` (sent automatically by the
CLI when it can read `/var/lib/mcp_bridge/state/daemon.pid`).

---

## Protocol — native MCP over JSON-RPC 2.0

The daemon speaks **MCP** ([Model Context Protocol](https://modelcontextprotocol.io))
over streamable HTTP. Connect with Claude Desktop, Cursor, LangChain
`MultiServerMCPClient`, or any MCP-compatible client by pointing it at:

```
http://<host>:8080/
Authorization: Bearer <your token>
```

Methods supported (JSON-RPC 2.0 envelope):

| Method                       | Purpose                                                  |
|------------------------------|----------------------------------------------------------|
| `initialize`                 | Handshake; server returns `Mcp-Session-Id` in the header |
| `notifications/initialized`  | Client→server notification, no reply                     |
| `ping`                       | Liveness                                                 |
| `tools/list`                 | All registered tools with their `inputSchema`            |
| `tools/call`                 | Invoke a tool — params: `{name, arguments}`              |
| `shutdown`                   | Tears down the session                                   |

Every method except `initialize` requires the `Mcp-Session-Id` header echoed
back from the `initialize` response. A session is bound to the bearer hash
that issued it; rotating that user's token invalidates every active session.

### Raw curl example

```bash
TOKEN="<your token>"
URL="http://localhost:8080/"

# 1. initialize, capture session id
SESS=$(curl -sS -D - -X POST "$URL" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}' \
    | awk 'tolower($1)=="mcp-session-id:"{print $2}' | tr -d '\r')

# 2. list tools
curl -sS -X POST "$URL" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -H "Mcp-Session-Id: $SESS" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# 3. call ping
curl -sS -X POST "$URL" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -H "Mcp-Session-Id: $SESS" \
    -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}'
```

Server-sent events for server→client notifications are available at
`GET /` (same auth + session id required); v1 emits a `ready` event at
connect and 30-second heartbeats. Tool-call results return on the POST.

### JSON-RPC error codes

| Code     | When                                     |
|----------|------------------------------------------|
| `-32700` | Body is not parseable JSON               |
| `-32600` | Envelope is not valid JSON-RPC, or session is missing/mismatched |
| `-32601` | Unknown method                           |
| `-32602` | Bad / missing params (incl. tool args)   |
| `-32603` | Internal error                           |

### Public probe

`GET /healthz` returns `ok` without auth — useful for load-balancer probes.
It deliberately does **not** expose tool metadata; that's `tools/list`.

---

## Privilege escalation (sudoers grants)

The daemon runs as a non-privileged user `mcp` (not in the sudo group). For
operations that need root, it issues **time-limited sudoers drop-ins** via a
setuid helper at `/usr/lib/mcp_bridge/mcp_bridge-priv` (mode 4750, root:mcp).

Templates are operator-defined in `mcp.json`:

```jsonc
"sudo_grant_templates": [
  {
    "name": "systemctl_restart",
    "binary": "/usr/bin/systemctl",
    "argv":   ["restart", "{service}"],
    "params": { "service": "^[a-z0-9._-]+$" }
  }
]
```

Tools call the daemon-internal `request_grant(ctx, shortid, template, args, ttl)`
API; the daemon validates the captured args against each `params` regex,
charset-checks the rendered command (no shell metacharacters), atomically
writes the spec to `/var/lib/mcp_bridge/state/`, invokes the helper, which
re-validates the spec shape, runs `visudo -cf`, and renames into
`/etc/sudoers.d/mcp_grant_<grantid>`. A sweeper thread revokes expired
grants; a startup reconciler removes orphans left by crashed daemons. Every
operation emits a `LOG_AUTHPRIV` syslog line under the
`mcp-bridge-sudoers` identifier — `journalctl -t mcp-bridge-sudoers`.

The admin-only HTTP tools `grant_request` and `grant_revoke` expose this
to MCP clients.

---

## Available Tools

67 tools across 9 modules.

### Data — Files (12 tools)

| Tool | Required Args | Optional Args | Description |
|------|--------------|---------------|-------------|
| `list_files` | | `path` | List directory contents with metadata |
| `read_file` | `path` | `offset`, `limit` | Read file contents |
| `write_file` | `path`, `content` | `create_dirs` | Write/overwrite file |
| `delete_file` | `path` | `recursive` | Delete file or directory |
| `move_file` | `source`, `destination` | | Move or rename |
| `copy_file` | `source`, `destination` | `recursive` | Copy file or directory |
| `search_files` | `pattern` | `path`, `type`, `recursive` | Search by name or content regex |
| `file_info` | `path` | | Get size, permissions, timestamps |
| `set_permissions` | `path`, `mode` | `recursive` | chmod (octal string, e.g. `"755"`) |
| `set_owner` | `path`, `owner` | `group`, `recursive` | chown (Linux only) |
| `create_directory` | `path` | `recursive` | Create directory |
| `disk_usage` | | `path` | Get disk space information |

### Data — Database (16 tools)

| Tool | Required Args | Optional Args | Description |
|------|--------------|---------------|-------------|
| `list_databases` | | `engine` | List all databases |
| `create_database` | `name` | `engine` | Create a database |
| `delete_database` | `name` | `engine` | Drop a database |
| `list_db_users` | | `engine` | List database users |
| `create_db_user` | `username`, `password` | `engine` | Create user |
| `delete_db_user` | `username` | `engine` | Drop user |
| `grant_privileges` | `username`, `database` | `privileges`, `engine` | Grant privileges |
| `revoke_privileges` | `username`, `database` | `engine` | Revoke privileges |
| `run_query` | `database`, `query` | `engine` | Execute SQL query |
| `run_query_file` | `database`, `path` | `engine` | Execute SQL file |
| `backup_database` | `database` | `path`, `engine` | Dump database to file |
| `restore_database` | `database`, `path` | `engine` | Restore from dump file |
| `list_tables` | `database` | `engine` | List tables |
| `describe_table` | `database`, `table` | `engine` | Show table schema |
| `db_server_info` | | `engine` | Server version and status |
| `check_database` | `database` | `engine` | Check database integrity |

The `engine` argument defaults to `"mysql"`. Set to `"postgres"` for PostgreSQL.
`run_query` and `run_query_file` require `security.enable_raw_queries: true` in `mcp.json`.

### Networking — Ports (5 tools)

| Tool | Required Args | Optional Args | Description |
|------|--------------|---------------|-------------|
| `list_listening_ports` | | | Show all listening ports |
| `check_port` | `port` | `host` | Check if port is open |
| `start_listener` | `port` | `protocol`, `response` | Start a managed TCP listener |
| `stop_listener` | `port` | | Stop a managed listener |
| `list_listeners` | | | List active managed listeners |

### Networking — Firewall (5 tools)

| Tool | Required Args | Optional Args | Description |
|------|--------------|---------------|-------------|
| `list_firewall_rules` | | | List current firewall rules |
| `add_firewall_rule` | `port`, `action` | `protocol`, `source_ip`, `direction` | Add allow/deny rule |
| `delete_firewall_rule` | `rule_id` | | Delete rule by ID |
| `add_port_forward` | `source_port`, `dest_host`, `dest_port` | `protocol` | Create port forward |
| `delete_port_forward` | `source_port` | | Remove port forward |

Uses `iptables` on Linux, `netsh advfirewall` on Windows.

### Hosting — Web Server (11 tools)

| Tool | Required Args | Optional Args | Description |
|------|--------------|---------------|-------------|
| `webserver_status` | | `server` | Check if running, get version |
| `webserver_start` | | `server` | Start web server |
| `webserver_stop` | | `server` | Stop web server |
| `webserver_restart` | | `server` | Restart web server |
| `webserver_reload` | | `server` | Reload configuration |
| `webserver_test_config` | | `server` | Test configuration syntax |
| `list_vhosts` | | `server` | List virtual hosts |
| `get_vhost_config` | `domain` | `server` | Read vhost config file |
| `create_vhost` | `domain`, `root` | `server`, `port`, `ssl` | Create virtual host |
| `delete_vhost` | `domain` | `server` | Remove virtual host |
| `enable_ssl` | `domain` | `cert_path`, `key_path` | Enable SSL (certbot or manual) |

The `server` argument auto-detects between `"nginx"` and `"apache"` if omitted.

### Hosting — Processes (3 tools)

| Tool | Required Args | Optional Args | Description |
|------|--------------|---------------|-------------|
| `list_processes` | | `filter` | List running processes |
| `kill_process` | `pid` | `signal` | Kill process by PID |
| `process_info` | `pid` | | Get process details |

### Command Execution (5 tools)

| Tool | Required Args | Optional Args | Description |
|------|--------------|---------------|-------------|
| `run_command` | `command` | `cwd`, `timeout`, `env` | Execute command, return output |
| `run_background` | `command` | `cwd`, `env`, `name` | Start background process |
| `list_background` | | | List managed background processes |
| `kill_background` | `pid` | `signal` | Kill background process |
| `get_output` | `pid` | `lines` | Get background process output |

### Sandboxed Code Execution (4 tools)

| Tool | Required Args | Optional Args | Description |
|------|--------------|---------------|-------------|
| `sandbox_run` | `language`, `code` | `timeout`, `memory_mb`, `stdin` | Execute code in sandbox |
| `sandbox_run_file` | `language`, `path` | `timeout`, `memory_mb`, `stdin`, `args` | Execute file in sandbox |
| `sandbox_languages` | | | List available languages |
| `sandbox_status` | | | Show sandbox isolation capabilities |

Supported languages: `python`, `node`, `bash`, `sh`, `ruby`, `perl`, `php`, `c`, `cpp`, `go`, `rust`.

Isolation levels:
- **High** — Bubblewrap available (filesystem, PID, and network namespace isolation)
- **Medium** — Linux namespaces via `unshare`
- **Basic** — `ulimit` + `timeout` fallback

### Built-in (1 tool)

| Tool | Description |
|------|-------------|
| `ping` | Health check, returns `{"pong": true}` |

### Admin (5 tools, admin-only)

| Tool | Required Args | Optional Args | Description |
|------|--------------|---------------|-------------|
| `grant_request` | `shortid`, `template`, `captured_args`, `ttl_seconds` | | Issue a time-limited sudoers drop-in via the privileged helper. |
| `grant_revoke`  | `grantid` | | Revoke a previously-issued drop-in. Idempotent. |
| `user_create`   | `name`, `email` | `is_admin` | Provision a new MCP user — generates shortid + bearer token, writes the user record, and creates the `mcp_user_<shortid>` POSIX account via the helper. **The returned token is shown once.** |
| `user_update`   | `shortid` | `name`, `email`, `is_admin` | Update a user's mutable details. At least one optional field must be supplied. Token is unaffected — use `auth rotate` for that. |
| `user_delete`   | `shortid` | | Delete the user record and remove the `mcp_user_<shortid>` POSIX account. Idempotent on the OS side. Refuses to delete the calling user. |

The same operations are available offline via the [`mcp_bridge auth …`](#provisioning-users) CLI. Tool-based provisioning is a convenience for AI-driven onboarding flows; treat the returned bearer token from `user_create` as one-shot.

---

## Usage examples

All examples assume the bearer token is in `$TOKEN` and the `Mcp-Session-Id`
captured from `initialize` is in `$SESS` — see the curl example in the
Protocol section above. Every call is `tools/call` with `{name, arguments}`.

### List files

```bash
curl -sS -X POST "$URL" \
  -H "Authorization: Bearer $TOKEN" -H "Mcp-Session-Id: $SESS" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":10,"method":"tools/call",
       "params":{"name":"list_files","arguments":{"path":"/var/www"}}}'
```

### Create an Nginx virtual host

```bash
curl -sS -X POST "$URL" \
  -H "Authorization: Bearer $TOKEN" -H "Mcp-Session-Id: $SESS" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":11,"method":"tools/call",
       "params":{"name":"create_vhost",
                 "arguments":{"domain":"mysite.example.com",
                              "root":"/var/www/mysite","server":"nginx"}}}'
```

### Run a SQL query

```bash
curl -sS -X POST "$URL" \
  -H "Authorization: Bearer $TOKEN" -H "Mcp-Session-Id: $SESS" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":12,"method":"tools/call",
       "params":{"name":"run_query",
                 "arguments":{"database":"myapp",
                              "query":"SELECT COUNT(*) FROM users;"}}}'
```

### Execute Python in the sandbox

```bash
curl -sS -X POST "$URL" \
  -H "Authorization: Bearer $TOKEN" -H "Mcp-Session-Id: $SESS" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":13,"method":"tools/call",
       "params":{"name":"sandbox_run",
                 "arguments":{"language":"python",
                              "code":"print(sum(range(100)))",
                              "timeout":10,"memory_mb":128}}}'
```

### Issue a sudoers grant (admin only)

```bash
curl -sS -X POST "$URL" \
  -H "Authorization: Bearer $TOKEN" -H "Mcp-Session-Id: $SESS" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":14,"method":"tools/call",
       "params":{"name":"grant_request",
                 "arguments":{"shortid":"abc23456",
                              "template":"systemctl_restart",
                              "captured_args":{"service":"nginx"},
                              "ttl_seconds":300}}}'
```

### Provision a new user (admin only)

```bash
curl -sS -X POST "$URL" \
  -H "Authorization: Bearer $TOKEN" -H "Mcp-Session-Id: $SESS" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":15,"method":"tools/call",
       "params":{"name":"user_create",
                 "arguments":{"name":"Bob","email":"bob@example.com"}}}'
# response.result.token is the new user's bearer — capture it now, it cannot be retrieved later.
```

---

## Context Tracking

The bridge maintains a `context.json` file that is auto-created on the first request. Some tools (e.g. `list_databases`) update context with their results for cross-tool awareness by AI agents.

---

## Logging

Three log surfaces, all populated by every running daemon:

1. **systemd journal** — the `.service` unit has `StandardOutput=journal` and
   `SyslogIdentifier=mcp_bridge`, so every line spdlog writes lands in
   journald. This is the recommended interface post-install:

   ```bash
   sudo journalctl -u mcp-bridge -f                  # follow
   sudo journalctl -u mcp-bridge --since "10 min ago"
   sudo journalctl -u mcp-bridge -p err              # warnings + errors only
   ```

   Each request produces a single info line of the form:

   ```
   [<ip>] user=<shortid|admin> sess=<8-char-prefix> method=<jsonrpc-method>
   ```

2. **Rotating file** — same content, written by spdlog's rotating-file sink
   (5 MB × 3 backups = 20 MB cap). Path is `logging.file` in `mcp.json`,
   defaulting to `/var/log/mcp_bridge/server.log`. Set to `""` if you want
   the journal sink only.

3. **Sudoers audit trail** — [`src/core/grants.cpp`](src/core/grants.cpp)
   emits a separate stream via `syslog(LOG_AUTHPRIV, …)` under identifier
   `mcp-bridge-sudoers`. Every grant lifecycle event (`grant_issued`,
   `grant_failed`, `grant_revoked`, `grant_revoke_orphan`,
   `grant_reconciled`) lands there with `grantid`, `by` (user_id),
   `client_ip`, and per-event detail.

   ```bash
   sudo journalctl -t mcp-bridge-sudoers             # grant audit
   sudo journalctl -t mcp-bridge-sudoers -f
   ```

   On hosts that ship `/var/log/auth.log`, the same lines mirror there.

Log level is set by `logging.level` in `mcp.json` (`debug` | `info` | `warn`
| `error`). Changing it requires `systemctl restart mcp-bridge` —
`SIGHUP` only reloads user records, not log configuration.

---

## Rate Limiting

Default: 60 requests per minute per **authenticated user** (sliding 1-minute
window, idle buckets garbage-collected after 5 minutes). Configurable via
`security.rate_limit` in `mcp.json`. Returns HTTP 429 when exceeded.

---

## Security

- **Tokens stored as hashes.** `mcp.json` carries `auth.global_token_salt`
  and `auth.admin_token_hash`; user records carry `token_hash`. Plaintext
  tokens are shown only at creation/rotation time, on `/dev/tty`.
- **Daemon runs as a non-privileged `mcp` user**, not in the sudo group.
  Privileged ops go through the setuid helper at
  `/usr/lib/mcp_bridge/mcp_bridge-priv` (mode 4750, root:mcp).
- **Per-OS-user multi-tenancy.** Each provisioned user gets a POSIX account
  `mcp_user_<shortid>`, no shell, not in sudo. POSIX permissions and
  per-grant sudoers drop-ins are the authorization layer.
- **Sudoers grants are time-limited and reconciled on startup.** Operator-
  defined templates only — no free-form sudo specs cross the helper boundary.
- **`security.allowed_root`** restricts file operations to a base directory.
- **`security.allowed_ips`** restricts access to a specific list.
- **`security.enable_raw_queries=false`** disables `run_query` /
  `run_query_file` by default.
- **`security.dangerous_tools_enabled=false`** disables destructive tools
  (delete, drop, kill).
- **Sandbox isolation** — sandboxed code runs without network access, with
  memory/time limits, in a restricted filesystem. Uses Bubblewrap, Linux
  namespaces, or `ulimit` depending on availability.
- **Constant-time hash comparison** for bearer auth and session bindings.
- **Database name validation** — only alphanumerics and underscore.

---

## Running as a Service

The `.deb` ships a hardened systemd unit at
`/usr/lib/systemd/system/mcp-bridge.service` (User=mcp, Group=mcp, plus
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes`,
`ProtectKernel*`, `PrivateTmp`, scoped `ReadWritePaths`). Operate it with:

```bash
sudo systemctl status   mcp-bridge
sudo systemctl restart  mcp-bridge
sudo systemctl reload   mcp-bridge   # equivalent to SIGHUP — picks up new users
sudo journalctl -u      mcp-bridge -f
sudo journalctl -t      mcp-bridge-sudoers   # sudoers-grant audit trail
```

If you're running outside the `.deb`, copy the unit file from
`debian/mcp-bridge.service`, install the binary at `/usr/bin/mcp_bridge`
and the helper at `/usr/lib/mcp_bridge/mcp_bridge-priv` (mode 4750, root:mcp),
then `systemctl daemon-reload && systemctl enable --now mcp-bridge`.

---

## Testing

The repo ships an in-tree minimal test framework — no external dependencies —
under [`tests/`](tests/). Build with `BUILD_TESTS=ON` and run via `ctest`:

```bash
cmake -B build -DBUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Six binaries cover the load-bearing modules:

| Binary                | Cases | Covers                                                                                |
|-----------------------|-------|---------------------------------------------------------------------------------------|
| `test_crypto`         |  6    | SHA-256 known vectors, salted hex, constant-time compare, hex encoding                |
| `test_shortid`        |  6    | `make_shortid` charset/length/distinctness, `make_token`, UUIDv4 shape                |
| `test_jsonrpc`        | 12    | Request/notification parse, batch rejection, error-code constants, response shape     |
| `test_session`        |  7    | Issue + validate, cross-bearer rejection, idle expiry, last-seen extension, rotation  |
| `test_grant_template` | 18    | Template parse, regex/charset rejection, rendered spec shape (visudo gate, defense)   |
| `test_user_store`     |  5    | Empty/missing dir, load + lookup, reload picks up + drops users, malformed file skip  |

End-to-end tests against a running daemon are not part of `ctest`; they live
in the project's verification scripts and require launching the binary with
a synthesized JSON config (the patterns are documented in `installer/release.md`).

---

## Extending

To add a new tool module:

1. Create `src/tools/yourmodule/your_tools.hpp` with a `register_your_tools()` declaration
2. Create `src/tools/yourmodule/your_tools.cpp` with tool implementations
3. Add the `.cpp` file to `TOOL_SOURCES` in `CMakeLists.txt`
4. Include the header and call `register_your_tools()` in `src/main.cpp`

Each tool is registered with:

```cpp
ToolRegistry::instance().register_tool("tool_name", {
    "", "Description of the tool",
    {"required_arg1", "required_arg2"},  // validated before handler is called
    {"optional_arg1"},
    [](const RequestContext& ctx, const json& args) -> json {
        // ctx carries user_id, os_username, is_admin, session_id, bearer_hash, client_ip
        // For admin-gated tools, refuse early: if (!ctx.is_admin) throw …;
        return {{"key", "value"}};
    }
});
```

Admin-only tools live under `src/tools/admin/`. The daemon-internal
`Server::grants().request_grant(...)` is the only sanctioned way to obtain
a temporary sudoers drop-in — never shell out to `sudo` from a tool.

---

## License

MIT License

Copyright (c) 2026
