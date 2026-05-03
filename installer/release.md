# Release checklist

Per-release steps to publish a new `mcp-bridge` build.

## 1. Build the .debs

The `release.yml` workflow at `.github/workflows/release.yml` runs on tag
push (`v*`) and produces three `.deb`s: `ubuntu-22.04`, `ubuntu-24.04`,
`debian-12`, all amd64. Each is named:

    mcp-bridge_<version>_<distro>_amd64.deb

## 2. Generate `.sha256` files

For each `.deb`, publish a sibling `.deb.sha256` containing the
`sha256sum`-format line. The installer at `installer/install.sh` requires
this file at `<deb-url>.sha256`.

    for f in *.deb; do sha256sum "$f" > "$f.sha256"; done

The CI workflow should be extended to upload these alongside the `.deb`s.

## 3. Update `installer/install.sh` if needed

`MCP_INSTALL_VERSION` defaults to the version pinned in the script.
On every release, bump:

    PKG_VERSION="${MCP_INSTALL_VERSION:-X.Y.Z-N}"

Users invoke with the env var to install a specific version:

    curl -fsSL https://<host>/install.sh | MCP_INSTALL_VERSION=2.0.0~rc1-1 bash

## 4. Host the installer

Publish `installer/install.sh` at a stable URL (e.g.
`https://<domain>/install.sh`). The file is fetched with
`curl -o- ... | bash`; users wanting to inspect first do
`curl -o- ... | less`. The hint to do that is on the first line of the script.

## 5. Apt repo (second-class path)

For users who don't want curl-pipe-bash, also push the .debs to an apt
repo. The CI workflow already includes a `publish-apt` job that pushes to
packagecloud when `vars.PACKAGECLOUD_REPO` and `secrets.PACKAGECLOUD_TOKEN`
are configured. After that lands, users can:

    curl -s https://packagecloud.io/install/repositories/<owner>/<repo>/script.deb.sh | sudo bash
    sudo apt install mcp-bridge

## 6. Smoke test

On a fresh container of each supported distro:

    curl -fsSL https://<host>/install.sh | bash

Confirm:
- The asterisk-infinity banner prints.
- The admin API token prints to `/dev/tty` and does **not** appear in
  `/var/log/apt/term.log`.
- `systemctl status mcp-bridge` is green.
- `id mcp` shows the user is **not** in the `sudo` group.
- `curl -X POST http://localhost:8080/ -H "Authorization: Bearer <token>" \
   -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}'`
  returns 200 and an `Mcp-Session-Id` header.
