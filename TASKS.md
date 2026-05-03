# mcp_bridge — Migration Tasks

Roadmap for migrating from the current HTTP+JSON server to a native MCP server with per-OS-user multi-tenancy.

---

## 1. Project rename (`server_mcp_bridge` → `mcp_bridge`)

- [ ] Rename top-level directory and the binary target.
- [ ] Update `CMakeLists.txt` `project()` name and output target name.
- [ ] Update Debian packaging: `debian/control` (Source/Package), `debian/rules`, `debian/changelog` (new version entry noting the rename), all `debian/server-mcp-bridge*` paths, the `.service` unit, and the postinst/postrm scripts.
- [ ] Repo-wide search/replace for `server-mcp-bridge` and `server_mcp_bridge` across `debian/`, `src/`, `README.md`, `CMakeLists.txt`, install docs.

## 2. Native MCP / JSON-RPC 2.0 transport

- [ ] Replace the current HTTP+JSON dispatch in `src/core/server.cpp` with a JSON-RPC 2.0 envelope (`jsonrpc`, `method`, `params`, `id`).
- [ ] Implement MCP lifecycle methods: `initialize`, `notifications/initialized`, `ping`, `shutdown`.
- [ ] Implement MCP tools surface: `tools/list` (built from the existing `tool_registry`), `tools/call`.
- [ ] Streamable HTTP transport: `POST /` for client→server JSON-RPC, `GET /` (SSE) for server→client notifications.
- [ ] Session management: issue `Mcp-Session-Id` on `initialize` response, require it on subsequent calls, refuse session reuse across different bearer tokens.
- [ ] Map errors to JSON-RPC error codes (`-32601` method not found, `-32602` invalid params, `-32603` internal error, etc.).
- [ ] Verification: connect with **Claude Desktop** and **LangChain `MultiServerMCPClient`** end-to-end.

## 3. Multi-user auth model

- [ ] Rewrite `src/core/auth.{cpp,hpp}` to support **N tokens → user mapping**, not a single shared key.
- [ ] **Hash tokens at rest** (e.g. SHA-256 over `salt || token`); store the hash in the user record, never the plaintext token.
- [ ] On request: hash incoming bearer, look up user record, attach a `User` object to the request `Context`.
- [ ] Extend `src/core/context.{cpp,hpp}` with `user_id`, `os_username`, `is_admin`.
- [ ] Per-user rate limits — key `rate_limiter` by `user_id`, not by IP or global.
- [ ] Session creation tied to bearer token; reject any attempt to reuse a session with a different token.

## 4. Config layout (replace `.env`)

- [ ] **Daemon config**: `/etc/mcp_bridge/mcp.json` (mode 0644, owned `root:mcp`) — replaces `.env.example`. Carries every key from `.env.example` (server, security, DB, web, sandbox, logging) plus the admin token hash.
- [ ] **Per-user records**: `/var/lib/mcp_bridge/users/{shortid}.json` (mode 0600, owned `mcp:mcp`).
- [ ] **Runtime state** (sessions if persisted, active sudoers grants): `/var/lib/mcp_bridge/state/`.
- [ ] **Logs**: `/var/log/mcp_bridge/`.
- [ ] Update `src/core/config.{cpp,hpp}` to parse JSON instead of dotenv (delete the dotenv path).
- [ ] Update `debian/postinst` to install the JSON template at `/etc/mcp_bridge/mcp.json` and generate the admin token there.
- [ ] Confirm: **no config in `~/.config`** anywhere — server state lives under `/etc` and `/var/lib`.

## 5. User provisioning (`mcp_bridge auth create`)

- [ ] CLI subcommand wired into the binary (or split into `mcp_bridge-cli` if cleaner).
- [ ] Interactive prompts: **name, email only** — no phone (PII minimization).
- [ ] `shortid` = 8-char base32 of a fresh UUID; OS username = `mcp_user_{shortid}` (always valid POSIX, no collisions, no name-derivation hazards).
- [ ] Create OS user via the setuid helper: no login shell, **not in sudo group**, home `/home/mcp_user_{shortid}`.
- [ ] Generate API token (`openssl rand -hex 32`); persist `{shortid, name, email, created_at, is_admin: false, token_hash, token_salt}` to `/var/lib/mcp_bridge/users/{shortid}.json`.
- [ ] Print MCP connection block (endpoint URL, `Authorization` header, token) **once**. No `auth show` for tokens — only `auth rotate`.
- [ ] First user (created at install time) gets `is_admin: true`.

## 6. Privilege model

- [ ] Daemon runs as the **non-privileged `mcp` system user, NOT in the sudo group**. Update the systemd unit accordingly.
- [ ] **Setuid helper** `/usr/lib/mcp_bridge/mcp_bridge-priv`, owned `root:mcp`, mode `4750`. Accepts a closed set of subcommands: `useradd`, `userdel`, `grant-sudo`, `revoke-sudo`. Strict whitelist input validation on every arg.
- [ ] No daemon code path writes to `/etc/sudoers.d` directly — everything goes through the helper.

## 7. Sudoers grant system

- [ ] **One file per grant**: `/etc/sudoers.d/mcp_grant_{grantid}`. Always validate with `visudo -cf` before install; reject on parse error.
- [ ] Active-grant state in `/var/lib/mcp_bridge/state/grants.json` with `{grantid, user, command, expires_at}`.
- [ ] Periodic sweep (in-daemon timer) removes expired drop-ins and updates state.
- [ ] On daemon startup, **reconcile**: any `/etc/sudoers.d/mcp_grant_*` not present in `grants.json` is removed (handles crashes mid-task).
- [ ] Audit: every grant/revoke emitted via `syslog(LOG_AUTHPRIV)` with identifier `mcp-bridge-sudoers`. Queryable: `journalctl -t mcp-bridge-sudoers`.
- [ ] Single API in `src/core/`: `request_grant(user, command, ttl)` / `revoke_grant(grantid)` — tools must use this, never roll their own.

## 8. Installer script (`curl | bash`)

- [ ] Hosted at `https://<domain>/install.sh`, invoked via `curl -o- ... | bash`.
- [ ] Inline helpers at the top: `require_sudo`, `detect_distro`, `detect_arch`, `download_with_checksum`, `style_banner`.
- [ ] Flow: check sudo → detect distro/arch → create system user `mcp` (no shell, **not in sudo group**) → download matching `.deb` + `.deb.sha256` → verify checksum → `apt install ./mcp_bridge_*.deb` → enable + start the service → run `mcp_bridge auth create` non-interactively for the admin → print the welcome banner.
- [ ] Hint at the top of the script: `# To inspect first: curl -o- <url> | less`.
- [ ] Publish `.deb.sha256` next to every released `.deb` for verification.
- [ ] Also publish an **apt repo** as a second-class path for users who don't want curl-pipe-bash.

## 9. Welcome banner

- [ ] Printed at end of install to the **operator's TTY** (write to `/dev/tty` directly so the API key doesn't get captured in `apt`'s persistent term log).
- [ ] Contents: install path, service status, **admin API key (shown once)**, MCP endpoint URL, example Claude Desktop client snippet, link to docs, **infinity-symbol ASCII art** (parent company logo).
- [ ] Also write the non-secret subset to `/etc/motd.d/mcp_bridge` for next-login visibility (no token here).

## 10. Cleanup

- [ ] Delete `.env.example` and the dotenv code path from `src/core/config.cpp`.
- [ ] Delete the legacy single-key auth path once the new model is in place.
- [ ] Tests under `tests/` covering: JSON-RPC envelope, MCP `initialize` / `tools/list` / `tools/call`, token-hash auth, session enforcement across tokens, grant create + revoke + startup-reconciliation.

---

## Locked-in decisions (reference)

1. Daemon runs **non-privileged** + scoped via setuid helper, **not** in the sudo group.
2. Config in `/etc/mcp_bridge/` and `/var/lib/mcp_bridge/`, **not** `~/.config`.
3. Tokens stored as **hashes**, shown only at creation.
4. OS usernames derived from **UUID shortids**, not from human names.
5. Sudoers grants via **per-grant drop-in files** with TTL + startup reconciliation.

## Explicitly deferred / declined

- Pinning the installer URL to a version (per `nvm`'s pattern) — not adopting; will track latest at a stable URL.
