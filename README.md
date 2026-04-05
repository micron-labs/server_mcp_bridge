# Server MCP Bridge

A lightweight C++ API bridge that exposes server management functionality to external systems such as MCP servers or AI agents. Designed for VPS and self-hosted servers (no cPanel required).

Provides programmatic management of files, databases, networking, web servers, processes, command execution, and sandboxed code execution through a secure HTTP interface.

---

## Overview

The system runs as a single compiled binary on your server and provides:

- Token-based authentication
- Tool-based execution model (62 tools across 8 modules)
- Context tracking
- Logging (console + rotating file)
- Rate limiting
- Cross-platform support (Linux and Windows)

```
Client (MCP server, AI agent, automation)
  |
  |  HTTP POST with JSON
  v
Server MCP Bridge (this binary)
  |
  |  Executes directly on the host OS
  v
Server resources (files, databases, services, processes)
```

---

## Directory Structure

```
server_mcp_bridge/
  CMakeLists.txt          # Build system
  .env                    # Configuration (create from .env.example)
  .env.example            # Configuration template
  context.json            # Auto-created on first request
  logs/
    server.log            # Auto-created

  vendor/                 # Header-only dependencies
    httplib.h             # cpp-httplib (HTTP server)
    json.hpp              # nlohmann/json
    spdlog/               # spdlog (logging)

  src/
    main.cpp              # Entry point
    core/
      server.cpp/hpp      # HTTP server, routing, request dispatch
      config.cpp/hpp      # .env parser
      auth.cpp/hpp        # Bearer token verification
      rate_limiter.cpp/hpp # Per-IP rate limiting
      context.cpp/hpp     # context.json state tracking
      logger.cpp/hpp      # spdlog initialization
      response.hpp        # JSON response helpers
    registry/
      tool_registry.cpp/hpp  # Tool map and discovery
      tool_types.hpp         # ToolDef struct, handler signature
    platform/
      platform.hpp           # Cross-platform interface
      linux/                 # Linux implementations
      windows/               # Windows implementations
    tools/
      data/
        file_ops.cpp/hpp       # 12 file management tools
        database_ops.cpp/hpp   # 16 database tools
      networking/
        port_ops.cpp/hpp       # 5 port/listener tools
        firewall_ops.cpp/hpp   # 5 firewall tools
      hosting/
        webserver_ops.cpp/hpp  # 11 Nginx/Apache tools
        process_mgmt.cpp/hpp   # 3 process management tools
      exec/
        command_ops.cpp/hpp    # 5 command execution tools
      sandbox/
        sandbox_ops.cpp/hpp    # 4 sandboxed code execution tools
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

## Setup

### 1. Build the Binary

Follow the [Build](#build) instructions above.

### 2. Create `.env` File

```bash
cp .env.example .env
```

Generate a secure API key:

```bash
openssl rand -hex 32
```

Edit `.env` and set at minimum:

```env
API_KEY=your_generated_token
PORT=8080
```

### 3. Set Permissions

```bash
chmod 600 .env
chmod 755 server_mcp_bridge
```

### 4. Run

```bash
./build/server_mcp_bridge
```

Or with a custom `.env` path:

```bash
./build/server_mcp_bridge --env /etc/mcp-bridge/.env
```

### 5. Verify

List all available tools (no auth required):

```bash
curl http://localhost:8080/?tools
```

Test a tool:

```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool": "ping", "args": {}}'
```

---

## Configuration

All settings are defined in `.env`. See [.env.example](.env.example) for defaults.

| Variable | Default | Description |
|----------|---------|-------------|
| **`API_KEY`** | *(required)* | Bearer token for authenticating requests |
| `HOST` | `0.0.0.0` | Listen address |
| `PORT` | `8080` | Listen port |
| `ENABLE_SSL` | `false` | Enable HTTPS |
| `SSL_CERT` | | Path to SSL certificate |
| `SSL_KEY` | | Path to SSL private key |
| `ALLOWED_IPS` | *(empty = all)* | Comma-separated IP allowlist |
| `RATE_LIMIT` | `60` | Max requests per minute per IP |
| `ALLOWED_ROOT` | `/` | Base path for file operations (path traversal protection) |
| `DANGEROUS_TOOLS_ENABLED` | `true` | Enable destructive tools |
| `ENABLE_RAW_QUERIES` | `false` | Allow `run_query` and `run_query_file` tools |
| `MYSQL_HOST` | `localhost` | MySQL/MariaDB host |
| `MYSQL_PORT` | `3306` | MySQL/MariaDB port |
| `MYSQL_ROOT_USER` | `root` | MySQL admin user |
| `MYSQL_ROOT_PASSWORD` | | MySQL admin password |
| `POSTGRES_HOST` | `localhost` | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_ROOT_USER` | `postgres` | PostgreSQL admin user |
| `POSTGRES_ROOT_PASSWORD` | | PostgreSQL admin password |
| `NGINX_CONFIG_DIR` | `/etc/nginx` | Nginx configuration directory |
| `APACHE_CONFIG_DIR` | `/etc/apache2` | Apache configuration directory |
| `CERTBOT_PATH` | `/usr/bin/certbot` | Path to certbot binary |
| `SANDBOX_TEMP_DIR` | `/tmp/mcp_sandbox` | Temp directory for sandbox execution |
| `SANDBOX_DEFAULT_TIMEOUT` | `30` | Default sandbox timeout (seconds) |
| `SANDBOX_DEFAULT_MEMORY_MB` | `256` | Default sandbox memory limit (MB) |
| `SANDBOX_ENABLE_NETWORK` | `false` | Allow network access in sandbox |
| `LOG_FILE` | `logs/server.log` | Log file path |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

---

## Authentication

All tool execution requests require a Bearer token:

```
Authorization: Bearer YOUR_API_KEY
```

The `GET /?tools` listing endpoint does **not** require authentication.

---

## Request Format

```http
POST /
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "tool": "tool_name",
  "args": {
    "param1": "value1",
    "param2": "value2"
  }
}
```

## Response Format

Success:

```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```

Error:

```json
{
  "success": false,
  "data": null,
  "error": "Error message"
}
```

HTTP status codes: `200` success, `400` bad request, `401` unauthorized, `403` forbidden, `429` rate limited, `500` internal error.

---

## Available Tools

62 tools across 8 modules.

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
`run_query` and `run_query_file` require `ENABLE_RAW_QUERIES=true` in `.env`.

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

---

## Usage Examples

### List files

```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool": "list_files", "args": {"path": "/var/www"}}'
```

### Create Nginx virtual host

```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "create_vhost",
    "args": {
      "domain": "mysite.example.com",
      "root": "/var/www/mysite",
      "server": "nginx"
    }
  }'
```

### Run a SQL query

```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "run_query",
    "args": {
      "database": "myapp",
      "query": "SELECT COUNT(*) FROM users;"
    }
  }'
```

### Execute Python code in sandbox

```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "sandbox_run",
    "args": {
      "language": "python",
      "code": "print(sum(range(100)))",
      "timeout": 10,
      "memory_mb": 128
    }
  }'
```

### Open a firewall port

```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "add_firewall_rule",
    "args": {
      "port": 3000,
      "action": "allow",
      "protocol": "tcp"
    }
  }'
```

---

## Context Tracking

The bridge maintains a `context.json` file that is auto-created on the first request. Some tools (e.g. `list_databases`) update context with their results for cross-tool awareness by AI agents.

---

## Logging

All tool executions are logged to the console and to `logs/server.log` (rotating, 5MB max, 3 backups). Log output includes timestamps, client IP, tool name, and arguments.

---

## Rate Limiting

Default: 60 requests per minute per IP address. Configurable via `RATE_LIMIT` in `.env`. Returns HTTP 429 when exceeded.

---

## Security

- **Protect `.env`** — never commit it or expose it publicly. Set `chmod 600`.
- **Use a strong, random `API_KEY`** — generated with `openssl rand -hex 32`.
- **`ALLOWED_ROOT`** — restricts file operations to a base directory, preventing path traversal.
- **`ALLOWED_IPS`** — restricts access to specific IP addresses.
- **`ENABLE_RAW_QUERIES=false`** — raw SQL execution is disabled by default.
- **`DANGEROUS_TOOLS_ENABLED=false`** — disables destructive tools (delete, drop, kill).
- **Sandbox isolation** — sandboxed code runs without network access, with memory/time limits, in a restricted filesystem. Uses Bubblewrap, namespaces, or ulimit depending on availability.
- **Constant-time auth** — Bearer token comparison resists timing attacks.
- **Database name validation** — only alphanumeric and underscore characters accepted.

---

## Running as a Service

### systemd (Linux)

Create `/etc/systemd/system/mcp-bridge.service`:

```ini
[Unit]
Description=Server MCP Bridge
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/mcp-bridge
ExecStart=/opt/mcp-bridge/server_mcp_bridge
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable mcp-bridge
sudo systemctl start mcp-bridge
```

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
    [](const json& args) -> json {
        // implementation
        return {{"key", "value"}};
    }
});
```

---

## License

MIT License

Copyright (c) 2026
