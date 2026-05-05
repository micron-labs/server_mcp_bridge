# Windows port — task plan

This is the plan to bring `mcp_bridge` to Windows parity with the Linux build,
covering the privilege module, the grant model, build/packaging, and the
installer. Phase ordering matters: nothing in Phase 2 lands cleanly without
Phase 1, and Phase 4 (installer) depends on Phase 3 (packaging).

## Phase 0 — current state (audit)

Already in place:

- `if(WIN32)` guards in [CMakeLists.txt:55,84](CMakeLists.txt#L55) select `src/platform/windows/*.cpp` and link `ws2_32`+`iphlpapi`.
- [.github/workflows/release.yml:68-107](.github/workflows/release.yml#L68-L107) builds `mcp-bridge-windows-amd64.exe` on `windows-latest` per release tag.
- Stubs exist for: `run_process`, `spawn_background`, `kill_process_by_pid`, `list_processes` ([src/platform/windows/process_windows.cpp](src/platform/windows/process_windows.cpp)).
- Release notes ([.github/workflows/release.yml:167-171](.github/workflows/release.yml#L167-L171)) mention running the .exe directly with `--config <path>`.

Gaps blocking a real Windows release:

- No privilege-escalation module (the `priv/main.c` setuid helper is excluded from Windows builds at [CMakeLists.txt:140](CMakeLists.txt#L140)).
- `run_process_as` and `spawn_background_as` ignore `os_username` ([src/platform/windows/process_windows.cpp:73-83](src/platform/windows/process_windows.cpp#L73-L83), `:105-110`). Auth identity is not enforced at exec time.
- No grant model (no Windows analog to `/etc/sudoers.d/mcp_grant_*`).
- No installer, no Windows Service registration, no postinst-analog (token/salt generation, user provisioning).
- No SHA256 sidecar for Windows artifacts.
- No code signing.
- No CI gate that fails the build if the Windows priv module is unimplemented.

---

## Phase 1 — Windows privilege module

**Goal:** a Windows analog of `mcp_bridge-priv` so the daemon can request privileged operations without itself running as `LocalSystem`.

### Design decision: Privileged Service over Named Pipe

Windows has no setuid. The closest faithful translation of "the daemon, running as a low-privilege account, asks a small audited helper to perform a privileged operation" is:

- **Daemon** runs under a virtual service account `NT SERVICE\mcp_bridge` (low privilege, no admin rights).
- **`mcp_bridge_priv.exe`** runs as a **separate Windows Service** under `LocalSystem`.
- They communicate over a **named pipe** at `\\.\pipe\mcp_bridge_priv` with an ACL that *only* allows the daemon's service SID to connect.
- The pipe wire format is line-delimited JSON; subcommands mirror the Linux helper one-to-one.

This keeps the trust boundary explicit (two processes, two SIDs, one pipe) and gives you a single audit point for every privileged action. A daemon RCE does not give attacker `LocalSystem`.

### Subcommands

Linux helper → Windows service RPC:

| Linux | Windows analog | Backing API |
|---|---|---|
| `useradd <shortid>` | `CreateLocalUser(shortid)` | `NetUserAdd` + `NetLocalGroupAddMembers` (none — keep them out of `Administrators`) |
| `userdel <shortid>` | `DeleteLocalUser(shortid)` | `NetUserDel` |
| `install-grant <grantid>` | `InstallGrant(grantid)` | write to `C:\ProgramData\mcp_bridge\grants\<grantid>.json`, validate against template |
| `revoke-grant <grantid>` | `RevokeGrant(grantid)` | unlink the JSON file |
| `install-system-admin <shortid>` | `InstallSystemAdmin(shortid)` | write `C:\ProgramData\mcp_bridge\system_admin.json` (wildcard grant) |
| `revoke-system-admin` | `RevokeSystemAdmin()` | unlink |
| *(new on Windows)* `RunAs(shortid, command, elevated)` | impersonate or elevate-and-spawn | `LogonUser` → `DuplicateTokenEx` → optionally `AdjustTokenPrivileges` for full admin → `CreateProcessAsUser` |

The `RunAs` call is the **inversion** of the Linux model: on Linux the daemon itself does `setuid`+`execve` (with `CAP_SETUID`); on Windows the priv service performs the spawn because only `LocalSystem` can `LogonUser` arbitrary local accounts without storing their plaintext passwords.

### Tasks

- [ ] **1.1** Create `src/priv_win/main.cpp` — Windows Service entry point, named-pipe server loop, JSON request dispatcher. Keep this in C++ (not C) so we can reuse the JSON parser.
- [ ] **1.2** Define the pipe ACL: only allow connection from the daemon's service SID (`SECURITY_ATTRIBUTES` with a hand-rolled DACL). Reject otherwise.
- [ ] **1.3** Implement `CreateLocalUser` / `DeleteLocalUser` via `NetUserAdd` / `NetUserDel`. Generate a random password the helper never persists (stored only as the LSA secret for that account, recovered via `LsaRetrievePrivateData` for `LogonUser`). Alternative: use `LogonUser` with `LOGON32_LOGON_SERVICE` + `LOGON32_PROVIDER_DEFAULT` against an account flagged `UF_PASSWD_CANT_CHANGE | UF_DONT_EXPIRE_PASSWD`, password generated and immediately stored as an LSA secret.
- [ ] **1.4** Implement `RunAs` — the elevated path needs `SE_ASSIGNPRIMARYTOKEN_NAME` and `SE_INCREASE_QUOTA_NAME` privileges (LocalSystem has these by default). Plumb stdout/stderr back via the pipe. Mirror the exit-code conventions from `run_process` (return value, stderr_str on privilege-drop failure).
- [ ] **1.5** Add CMake target `mcp_bridge_priv` enabled only on Windows (mirror the Linux `mcp_bridge-priv` block at [CMakeLists.txt:140-144](CMakeLists.txt#L140-L144)).
- [ ] **1.6** Replace [src/platform/windows/process_windows.cpp:73-110](src/platform/windows/process_windows.cpp#L73-L110) stubs with a client that talks to the priv service over the named pipe. Same `run_process_as` / `spawn_background_as` signatures the Linux side uses; `command_ops.cpp` doesn't need to know which platform it's on.
- [ ] **1.7** Add a build-time guard to `process_windows.cpp` that errors when `MCP_BRIDGE_PRODUCTION` is defined but the priv-pipe client isn't:

  ```cpp
  #if defined(MCP_BRIDGE_PRODUCTION) && !defined(MCP_BRIDGE_PRIV_PIPE_CLIENT)
  #error "Windows privilege drop is not implemented; not safe to ship"
  #endif
  ```

- [ ] **1.8** Audit-log every priv-service request to the Windows Event Log under a custom source `MCP-Bridge-Priv` so events show in Event Viewer alongside other security events.

**Acceptance:** `mcp_bridge_priv.exe` registered as a Windows Service, daemon as a separate service. End-to-end test: admin token issues a `tools/call run_command` for `whoami /priv` → priv service `RunAs` returns the elevated token's privilege set.

---

## Phase 2 — Grant model (Windows analog of sudoers drop-ins)

**Goal:** the same TTL/template/wildcard semantics the Linux `GrantManager` provides, encoded as files the priv service consults.

### Storage

- `C:\ProgramData\mcp_bridge\grants\<grantid>.json` — per-grant file, owned by `LocalSystem`, ACL denies write to anyone but `LocalSystem`. The shape mirrors the Linux spec but explicit-JSON instead of sudoers syntax:

  ```json
  {
    "grantid": "<16-hex>",
    "shortid": "<8-base32>",
    "sid": "S-1-5-21-…",            // bound to the local user's SID at issue time
    "template": "systemctl_restart",
    "command_pattern": "C:\\Windows\\System32\\sc.exe start nginx",
    "elevated": true,
    "expires_at": 1715000000
  }
  ```

- `C:\ProgramData\mcp_bridge\system_admin.json` — fixed-name file for the install admin's wildcard grant. Out of scope for the runtime grant reconciler. Same shape but `command_pattern: "*"`, no `expires_at` (or far-future).

### SID binding (defense in depth)

Linux `mcp_user_<shortid>` is identified by name. On Windows, account names can be reused but **SIDs are unique**. Bind grants to the SID at issue time:

- On `CreateLocalUser`, capture and persist the new account's SID.
- On `RunAs`, look up the live SID for the username and *fail* if it doesn't match the SID stored in the grant. Closes the "username got recreated, old grant still authoritative" footgun.

### Tasks

- [ ] **2.1** `src/core/grant_template.cpp::render_full_admin_spec` already produces the Linux wildcard line. Add `render_windows_grant_json` that produces the JSON shape above. Both must round-trip through `spec_is_well_formed`-style validation (rename to platform-aware: `validate_grant_record`).
- [ ] **2.2** Mirror the runtime reconciler ([src/core/grants.cpp:reconcile_at_startup](src/core/grants.cpp)) for the Windows store — sweep `grants\` and remove orphans; skip `system_admin.json`.
- [ ] **2.3** Implement command matching: by default, exact-match `command_pattern`. For `full_admin`, `*` wildcards. Do **not** support glob/regex in V1; matching must be auditable.
- [ ] **2.4** Update [src/tools/admin/grant_ops.cpp](src/tools/admin/grant_ops.cpp) so `grant_request` calls into a platform-abstract `GrantManager::request` — the Windows path goes through the priv pipe, not the Linux helper.
- [ ] **2.5** Document the privilege model differences in [README.md](README.md) — specifically that "elevated" on Windows means `Administrators`-equivalent token, not "root."
- [ ] **2.6** Tests: extend `test_grant_template.cpp` with the Windows JSON render + parse + validation cases. Skip the actual privilege-drop tests (they need a real Windows account).

**Acceptance:** on a Windows VM, `grant_request(template="full_admin", shortid="mcpadmin", ttl_seconds=3600)` writes a valid grant file, the priv service consults it on the next `RunAs` invocation, and `whoami /groups` from the admin's MCP session shows `BUILTIN\Administrators` enabled.

---

## Phase 3 — Build & packaging

**Goal:** ship a real Windows artifact: signed binaries, an installer that registers both services, and SHA256 sidecars for verification.

### Tasks

- [ ] **3.1** Extend the `build-binary` matrix entry for Windows in [.github/workflows/release.yml:94-101](.github/workflows/release.yml#L94-L101) to also build `mcp_bridge_priv.exe`.
- [ ] **3.2** Generate `.sha256` sidecars for the Windows artifacts in CI (today only `.deb`s get them — see [installer/release.md:18-22](installer/release.md#L18-L22)).
- [ ] **3.3** Add a WiX-based MSI build:
  - New repo path `installer/wix/mcp_bridge.wxs`.
  - Components: `mcp_bridge.exe` → `C:\Program Files\mcp_bridge\`, `mcp_bridge_priv.exe` → same, `mcp.json.template` → `C:\ProgramData\mcp_bridge\` (only if no existing config).
  - Two `<ServiceInstall>` blocks: one for the daemon under the virtual account `NT SERVICE\mcp_bridge`, one for the priv service under `LocalSystem`.
  - Custom action that runs the postinst-analog (token/salt generation, `useradd mcpadmin`, `install-system-admin mcpadmin`).
- [ ] **3.4** **Code signing.** Acquire an EV (or OV) Authenticode cert. CI signs the `.exe`s and the `.msi` with `signtool` before upload. Without this, SmartScreen will warn on every install. Defer if budget-blocked, but document the warning prominently in release notes until done.
- [ ] **3.5** Add a `win-installer` CI job that produces `mcp-bridge-${VERSION}-windows-amd64.msi` plus a `.sha256` sidecar.

**Acceptance:** `release.yml` produces a signed MSI. Installing it on a clean Windows Server VM registers both services, generates a token, prints it, and the daemon listens on `127.0.0.1:8080` (see Phase 4 for the bind-address default).

---

## Phase 4 — Installer script (`installer/install.ps1`)

**Goal:** the `bash | curl` user experience, but PowerShell. Also the on-ramp for users who don't use MSI.

The minimum viable script (committed today) handles the **daemon-only** path with stub priv. Once Phase 1 + Phase 3 ship, this script either pivots to invoking the MSI directly, or gains the steps that the MSI custom action would otherwise run.

### Tasks

- [ ] **4.1** Ship `installer/install.ps1` as an MVP that:
  - Self-elevates if not already running as Administrator.
  - Detects Windows version + arch.
  - Downloads `mcp-bridge-windows-amd64.exe` + `.sha256` from GitHub releases.
  - Verifies the SHA256.
  - Places binaries in `C:\Program Files\mcp_bridge\`.
  - Generates salt + admin token, writes `C:\ProgramData\mcp_bridge\mcp.json` from a template embedded in the script.
  - Registers a Windows Service via `sc.exe create`.
  - Starts the service.
  - Prints the admin token once.
- [ ] **4.2** Once Phase 1 lands, extend `install.ps1` to also fetch and register `mcp_bridge_priv.exe` as the LocalSystem service.
- [ ] **4.3** Once Phase 3 lands, switch the public-facing install path to MSI (`install.ps1` becomes a thin wrapper around `msiexec /i mcp-bridge-x.y.z.msi /qb`).
- [ ] **4.4** Add `installer/uninstall.ps1` — service stop, service delete (both), files removal, optional ProgramData cleanup mirroring Linux `postrm purge`.

---

## Phase 5 — CI / release pipeline

- [ ] **5.1** Add a *daily* Windows build on `main` (not just on tag push) so we catch platform regressions early. Today only tag pushes build Windows.
- [ ] **5.2** Add a Windows test job — at least the cross-platform unit tests (`test_crypto`, `test_jsonrpc`, `test_session`, `test_user_store`, `test_grant_template`). Skip the Linux-only ones (e.g. anything that touches setuid).
- [ ] **5.3** Update [installer/release.md](installer/release.md) to cover Windows steps: where the MSI is published, how to bump version, signing checklist.
- [ ] **5.4** Update GitHub release-notes template at [.github/workflows/release.yml:133-171](.github/workflows/release.yml#L133-L171) to point Windows users at `install.ps1` (today it tells them to invoke the .exe by hand).

---

## Phase 6 — Stretch / nice-to-have

- [ ] **6.1** Replace the named-pipe protocol with a more typed gRPC / Protobuf surface if the JSON line protocol gets unwieldy. *(Open — premature; revisit if the JSON wire format proves brittle.)*
- [x] **6.2** Sudo I/O logging analog: every elevated `RunAs` call appends a JSON record to `%ProgramData%\mcp_bridge\io_log\<YYYY-MM-DD>.log`. Always-on for elevated calls; non-elevated runs are not logged (would be noise from the bound user's normal shell). Output is bounded to 64 KiB per record. See [src/priv_win/operations.cpp](src/priv_win/operations.cpp).
- [ ] **6.3** TPM-backed token storage — instead of plain SHA256(salt||token), wrap the admin token hash in a TPM-sealed blob so a stolen disk image doesn't yield the hash. *(Open — needs TBS API integration; gate behind a config flag.)*
- [x] **6.4** Group Policy template (`.admx`) so org admins can deploy bridge config centrally. Scaffold at [installer/admx/mcp_bridge.admx](installer/admx/mcp_bridge.admx) + [installer/admx/en-US/mcp_bridge.adml](installer/admx/en-US/mcp_bridge.adml). The daemon's config loader doesn't yet read `HKLM\SOFTWARE\Policies\MCP-Bridge` — that wiring is the remaining work.
- [ ] **6.5** Windows-native sandboxing for the `sandbox_*` tools (App Containers / Windows Sandbox) — [src/platform/windows/sandbox_windows.cpp](src/platform/windows/sandbox_windows.cpp) already uses Job Objects with per-process memory caps. Full App Container isolation (capability-restricted token, separate filesystem view) is the open work.

---

## Effort estimate (rough)

| Phase | Engineer-days |
|---|---|
| 1 — Privilege module | 5–8 |
| 2 — Grant model | 2–3 |
| 3 — Build & packaging | 3–4 (excluding cert acquisition) |
| 4 — Installer script | 1–2 |
| 5 — CI / release | 1–2 |
| **Total to parity** | **~12–19 days** |

Stretch (Phase 6) is open-ended.

---

## Decision log

- **Why a separate priv service instead of running the daemon as LocalSystem:** preserves the property "RCE in the daemon ≠ root." Same reasoning as the Linux setuid-helper split. The cost is one extra service registration; the benefit is identical to Linux.
- **Why JSON over named pipe rather than COM/RPC:** simplest, fewest moving parts, easy to audit by tailing a log of pipe traffic. COM has a steeper auth/proxy surface that doesn't pay for itself at this scale.
- **Why bind to SID, not username:** Windows allows account-name reuse with a fresh SID. Without SID binding, a deleted-and-recreated `mcp_user_X` would silently inherit old grants.
- **Why exact-match commands in V1:** auditable. Glob/regex are escape hatches for an attacker who finds an injection in the template renderer; postpone to V2 only if real-world need shows up.
