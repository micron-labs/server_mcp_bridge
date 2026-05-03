#!/usr/bin/env bash
# To inspect first: curl -o- https://<domain>/install.sh | less
#
# Installs the latest mcp_bridge .deb on Debian / Ubuntu hosts.
# Verifies the SHA-256 checksum, runs apt install, enables the service, and
# prints a one-time admin connection block. Sets MCP_INSTALL_BASE to override
# the release URL (useful for staging).
set -euo pipefail

RELEASE_BASE="${MCP_INSTALL_BASE:-https://github.com/TheParadox20/server-mcp-bridge/releases/latest/download}"
PKG_VERSION="${MCP_INSTALL_VERSION:-2.0.0~rc1-1}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ----- helpers -----

require_sudo() {
    if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: must run as root, or install sudo." >&2
        exit 1
    fi
}

run_root() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

detect_distro() {
    [ -r /etc/os-release ] || { echo "ERROR: cannot read /etc/os-release" >&2; exit 1; }
    . /etc/os-release
    case "${ID:-}:${VERSION_ID:-}" in
        ubuntu:22.04) DISTRO=ubuntu-22.04 ;;
        ubuntu:24.04) DISTRO=ubuntu-24.04 ;;
        debian:12*)   DISTRO=debian-12    ;;
        ubuntu:*)
            DISTRO=ubuntu-22.04
            echo "WARNING: unknown Ubuntu ${VERSION_ID:-?}; trying ubuntu-22.04 build" >&2 ;;
        debian:*)
            DISTRO=debian-12
            echo "WARNING: unknown Debian ${VERSION_ID:-?}; trying debian-12 build" >&2 ;;
        *)
            echo "ERROR: unsupported distro ${ID:-unknown} ${VERSION_ID:-}" >&2
            echo "       supported: ubuntu 22.04/24.04, debian 12" >&2
            exit 1 ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) ARCH=amd64 ;;
        *) echo "ERROR: only amd64 is published right now (got $(uname -m))" >&2; exit 1 ;;
    esac
}

download_with_checksum() {
    local url="$1" out="$2"
    local sha_url="$url.sha256"
    echo "  fetching  $url"
    curl -fsSL "$url"     -o "$out"
    echo "  fetching  $sha_url"
    curl -fsSL "$sha_url" -o "$out.sha256"
    # The .sha256 file format is "<hash>  <filename>"; we only check the hash.
    local expected
    expected="$(awk '{print $1}' "$out.sha256")"
    local actual
    actual="$(sha256sum "$out" | awk '{print $1}')"
    if [ "$expected" != "$actual" ]; then
        echo "ERROR: checksum mismatch" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual"   >&2
        exit 1
    fi
    echo "  checksum  ok"
}

style_banner() {
    cat <<'EOF'

      ******         ******
    **      **     **      **
   *          *****          *
   *           ***           *
   *          *****          *
    **      **     **      **
      ******         ******

  MCP Bridge installed.

EOF
}

# ----- flow -----

require_sudo
detect_distro
detect_arch

DEB_NAME="mcp-bridge_${PKG_VERSION}_${DISTRO}_${ARCH}.deb"
URL="${RELEASE_BASE}/${DEB_NAME}"

echo "MCP Bridge installer"
echo "  distro:   $DISTRO"
echo "  arch:     $ARCH"
echo "  release:  $URL"
echo

download_with_checksum "$URL" "$TMP/$DEB_NAME"

echo
echo "  installing package …"
run_root apt-get install -y "$TMP/$DEB_NAME"

echo "  enabling and starting service …"
if [ -d /run/systemd/system ]; then
    run_root systemctl enable --now mcp-bridge
fi

style_banner
echo "  Above this banner, the postinst printed the admin API token to /dev/tty."
echo "  If you missed it, rotate the admin's user token with:"
echo "      sudo mcp_bridge auth rotate <shortid>"
echo "  Service status: sudo systemctl status mcp-bridge"
echo "  Config:         /etc/mcp_bridge/mcp.json"
echo
