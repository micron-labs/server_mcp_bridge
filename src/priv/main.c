// mcp_bridge-priv: setuid helper for the mcp_bridge daemon.
//
// Installed at /usr/lib/mcp_bridge/mcp_bridge-priv, mode 4750, owner root:mcp.
// Only the `mcp` group can execute it; the daemon (running as user `mcp`)
// reaches euid=0 inside this binary and performs a closed set of operations:
//
//   useradd <shortid>
//       creates system user mcp_user_<shortid>, no shell, not in sudo group.
//   userdel <shortid>
//       deletes system user mcp_user_<shortid>. Idempotent.
//   install-grant <grantid>
//       reads /var/lib/mcp_bridge/state/grant_<grantid>.spec, validates shape
//       (single line, charset-restricted, mcp_user_ prefix), runs `visudo -cf`
//       on it, then atomic-renames into /etc/sudoers.d/mcp_grant_<grantid>.
//   revoke-grant <grantid>
//       unlinks /etc/sudoers.d/mcp_grant_<grantid>. Idempotent.
//
// Exit codes:
//   0   success
//   10  argv validation failed
//   11  underlying syscall / subprocess failed
//   12  target absent (only useradd; revoke is idempotent)
//   13  visudo -cf rejected the rendered spec
//   14  target file already exists
//
// libc only — no external deps. Audit-friendly. Paths are compile-time
// constants so a compromised daemon cannot redirect the helper's writes.

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MCP_STATE_DIR
#define MCP_STATE_DIR "/var/lib/mcp_bridge/state"
#endif

#ifndef MCP_SUDOERS_DIR
#define MCP_SUDOERS_DIR "/etc/sudoers.d"
#endif

extern char** environ;

static int valid_shortid(const char* s) {
    if (!s) return 0;
    size_t n = strlen(s);
    if (n != 8) return 0;
    for (size_t i = 0; i < 8; ++i) {
        char c = s[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!ok) return 0;
    }
    return 1;
}

static int valid_grantid(const char* s) {
    if (!s) return 0;
    size_t n = strlen(s);
    if (n != 16) return 0;
    for (size_t i = 0; i < 16; ++i) {
        char c = s[i];
        int ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return 0;
    }
    return 1;
}

static int run(const char* path, char* const argv[]) {
    pid_t pid;
    int rc = posix_spawn(&pid, path, NULL, NULL, argv, environ);
    if (rc != 0) {
        fprintf(stderr, "posix_spawn %s: %s\n", path, strerror(rc));
        return -1;
    }
    int st;
    if (waitpid(pid, &st, 0) < 0) return -1;
    if (!WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}

static int cmd_useradd(int argc, char** argv) {
    if (argc != 1 || !valid_shortid(argv[0])) {
        fprintf(stderr, "usage: mcp_bridge-priv useradd <shortid>\n");
        return 10;
    }
    char username[32], home[64];
    snprintf(username, sizeof(username), "mcp_user_%s", argv[0]);
    snprintf(home, sizeof(home), "/home/%s", username);

    char* a[] = {"useradd", "-r", "-M", "-s", "/usr/sbin/nologin",
                 "-d", home, username, NULL};
    int rc = run("/usr/sbin/useradd", a);
    if (rc == 0) return 0;
    if (rc == 9) return 14;   // useradd: username already in use
    fprintf(stderr, "useradd exit=%d\n", rc);
    return 11;
}

static int cmd_userdel(int argc, char** argv) {
    if (argc != 1 || !valid_shortid(argv[0])) {
        fprintf(stderr, "usage: mcp_bridge-priv userdel <shortid>\n");
        return 10;
    }
    char username[32];
    snprintf(username, sizeof(username), "mcp_user_%s", argv[0]);

    char* a[] = {"userdel", "-r", username, NULL};
    int rc = run("/usr/sbin/userdel", a);
    if (rc == 0 || rc == 6) return 0;  // 6 = user does not exist (idempotent)
    fprintf(stderr, "userdel exit=%d\n", rc);
    return 11;
}

// Validates the spec content the daemon rendered. Defense in depth: a
// daemon compromise should not get arbitrary sudoers entries past this gate.
static int spec_well_formed(const char* buf, size_t len) {
    if (len == 0 || len > 4096) return 0;
    if (buf[len - 1] != '\n') return 0;
    for (size_t i = 0; i + 1 < len; ++i) {
        unsigned char c = (unsigned char)buf[i];
        if (c < 0x20 || c > 0x7e) return 0;
        if (c == '\n') return 0;  // exactly one trailing newline allowed
    }

    static const char prefix_a[] = "mcp_user_";
    if (len < strlen(prefix_a) + 8) return 0;
    if (memcmp(buf, prefix_a, strlen(prefix_a)) != 0) return 0;
    for (size_t i = 0; i < 8; ++i) {
        char c = buf[strlen(prefix_a) + i];
        int ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!ok) return 0;
    }
    static const char mid[] = " ALL=(root) NOPASSWD: /";
    if (memcmp(buf + strlen(prefix_a) + 8, mid, strlen(mid)) != 0) return 0;
    return 1;
}

static int cmd_install_grant(int argc, char** argv) {
    if (argc != 1 || !valid_grantid(argv[0])) {
        fprintf(stderr, "usage: mcp_bridge-priv install-grant <grantid>\n");
        return 10;
    }
    const char* grantid = argv[0];

    char spec_path[256];
    snprintf(spec_path, sizeof(spec_path), "%s/grant_%s.spec", MCP_STATE_DIR, grantid);

    int fd = open(spec_path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", spec_path, strerror(errno));
        return 11;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size > 4096) {
        close(fd);
        fprintf(stderr, "spec file rejected (not a regular file or too large)\n");
        return 13;
    }
    char buf[4097];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        fprintf(stderr, "spec file empty or unreadable\n");
        return 13;
    }
    buf[n] = '\0';
    if (!spec_well_formed(buf, (size_t)n)) {
        fprintf(stderr, "spec file failed shape check\n");
        return 13;
    }

    // Stage in sudoers.d as `.tmp.<grantid>`, run visudo -cf, rename into place.
    char tmp_path[256], final_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s/.mcp_grant_%s.tmp", MCP_SUDOERS_DIR, grantid);
    snprintf(final_path, sizeof(final_path), "%s/mcp_grant_%s", MCP_SUDOERS_DIR, grantid);

    // Refuse to install if the final target already exists.
    if (access(final_path, F_OK) == 0) {
        fprintf(stderr, "%s already exists\n", final_path);
        return 14;
    }

    int wfd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0440);
    if (wfd < 0) {
        fprintf(stderr, "open %s: %s\n", tmp_path, strerror(errno));
        return 11;
    }
    ssize_t off = 0;
    while (off < n) {
        ssize_t w = write(wfd, buf + off, (size_t)(n - off));
        if (w < 0) { close(wfd); unlink(tmp_path); return 11; }
        off += w;
    }
    if (fsync(wfd) != 0) { close(wfd); unlink(tmp_path); return 11; }
    close(wfd);

    if (chown(tmp_path, 0, 0) != 0) {
        unlink(tmp_path);
        fprintf(stderr, "chown %s: %s\n", tmp_path, strerror(errno));
        return 11;
    }

    char* a[] = {"visudo", "-cf", tmp_path, NULL};
    int rc = run("/usr/sbin/visudo", a);
    if (rc != 0) {
        unlink(tmp_path);
        fprintf(stderr, "visudo -cf failed (exit=%d)\n", rc);
        return 13;
    }

    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        fprintf(stderr, "rename %s -> %s: %s\n", tmp_path, final_path, strerror(errno));
        return 11;
    }
    return 0;
}

static int cmd_revoke_grant(int argc, char** argv) {
    if (argc != 1 || !valid_grantid(argv[0])) {
        fprintf(stderr, "usage: mcp_bridge-priv revoke-grant <grantid>\n");
        return 10;
    }
    char path[256];
    snprintf(path, sizeof(path), "%s/mcp_grant_%s", MCP_SUDOERS_DIR, argv[0]);
    if (unlink(path) == 0) return 0;
    if (errno == ENOENT) return 0;
    fprintf(stderr, "unlink %s: %s\n", path, strerror(errno));
    return 11;
}

int main(int argc, char** argv) {
    // Strip inherited environment; rebuild a minimal one for our own children.
    static char path_env[] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    static char* clean_env[] = {path_env, NULL};
    environ = clean_env;

    umask(0077);
    signal(SIGPIPE, SIG_DFL);

    if (argc < 2) {
        fprintf(stderr, "usage: %s <subcommand> [args...]\n", argv[0]);
        return 10;
    }

    if (strcmp(argv[1], "useradd") == 0)       return cmd_useradd(argc - 2, argv + 2);
    if (strcmp(argv[1], "userdel") == 0)       return cmd_userdel(argc - 2, argv + 2);
    if (strcmp(argv[1], "install-grant") == 0) return cmd_install_grant(argc - 2, argv + 2);
    if (strcmp(argv[1], "revoke-grant") == 0)  return cmd_revoke_grant(argc - 2, argv + 2);

    fprintf(stderr, "unknown subcommand: %s\n", argv[1]);
    return 10;
}
