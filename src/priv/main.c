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
//   install-system-admin <shortid>
//       writes a fixed `mcp_user_<shortid> ALL=(ALL) NOPASSWD: ALL` line into
//       /etc/sudoers.d/mcp_system_admin. Idempotent (overwrites). Used by
//       postinst to grant the install-time admin its sudo authority. The
//       fixed filename keeps it out of the runtime grant reconciler's scope.
//   revoke-system-admin
//       unlinks /etc/sudoers.d/mcp_system_admin. Idempotent.
//   prepare-user-state <shortid>
//       creates /var/lib/mcp_bridge/users_state/mcp_user_<shortid>/ and a
//       crons/ subdir, chown'd to the target user and mode 0700. Idempotent.
//   cleanup-user-state <shortid>
//       removes /var/lib/mcp_bridge/users_state/mcp_user_<shortid>/. Idempotent.
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
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MCP_STATE_DIR
#define MCP_STATE_DIR "/var/lib/mcp_bridge/state"
#endif

#ifndef MCP_SUDOERS_DIR
#define MCP_SUDOERS_DIR "/etc/sudoers.d"
#endif

#ifndef MCP_USERS_STATE_DIR
#define MCP_USERS_STATE_DIR "/var/lib/mcp_bridge/users_state"
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

// Spawn a child with stderr redirected to a pipe, then return its exit code and
// write (truncated) stderr into `errbuf` (always NUL-terminated).
static int run_capture_stderr(const char* path, char* const argv[],
                              char* errbuf, size_t errbuf_sz) {
    if (!errbuf || errbuf_sz == 0) return -1;
    errbuf[0] = '\0';

    int p[2];
    if (pipe(p) != 0) {
        snprintf(errbuf, errbuf_sz, "pipe: %s", strerror(errno));
        return -1;
    }
    // Best-effort CLOEXEC for both ends.
    (void)fcntl(p[0], F_SETFD, fcntl(p[0], F_GETFD) | FD_CLOEXEC);
    (void)fcntl(p[1], F_SETFD, fcntl(p[1], F_GETFD) | FD_CLOEXEC);

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    // Child stderr/stdout -> pipe write end.
    //
    // We intentionally capture stdout too: some shadow-utils builds emit certain
    // error lines on stdout, which would otherwise leak into journald.
    posix_spawn_file_actions_adddup2(&fa, p[1], STDERR_FILENO);
    posix_spawn_file_actions_adddup2(&fa, p[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&fa, p[0]);
    posix_spawn_file_actions_addclose(&fa, p[1]);

    pid_t pid;
    int rc = posix_spawn(&pid, path, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(p[1]); // parent reads from p[0]

    if (rc != 0) {
        snprintf(errbuf, errbuf_sz, "posix_spawn %s: %s", path, strerror(rc));
        close(p[0]);
        return -1;
    }

    size_t off = 0;
    while (off + 1 < errbuf_sz) {
        ssize_t n = read(p[0], errbuf + off, errbuf_sz - 1 - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        off += (size_t)n;
    }
    errbuf[off] = '\0';
    close(p[0]);

    int st;
    if (waitpid(pid, &st, 0) < 0) return -1;
    if (!WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}

static int fd_locked_by_fcntl(int fd) {
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0; // whole file
    if (fcntl(fd, F_SETLK, &fl) != 0) {
        if (errno == EACCES || errno == EAGAIN) return 1;
        return 0;
    }
    fl.l_type = F_UNLCK;
    (void)fcntl(fd, F_SETLK, &fl);
    return 0;
}

static pid_t lock_holder_pid_by_fcntl(int fd) {
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0; // whole file
    if (fcntl(fd, F_GETLK, &fl) != 0) return 0;
    if (fl.l_type == F_UNLCK) return 0;
    return fl.l_pid;
}

static int passwd_db_locked(void) {
    // shadow-utils uses advisory fcntl(2) locks (via lockf/lckpwdf) while
    // updating passwd/group/shadow. The presence of a lock *file* is not a
    // sufficient signal (e.g. /etc/.pwd.lock can exist permanently), so we
    // attempt to take a non-blocking fcntl write lock.
    const char* locks[] = {
        "/etc/passwd.lock",
        "/etc/shadow.lock",
        "/etc/group.lock",
        "/etc/gshadow.lock",
        "/etc/.pwd.lock",
    };
    for (size_t i = 0; i < sizeof(locks) / sizeof(locks[0]); ++i) {
        int fd = open(locks[i], O_RDWR | O_CLOEXEC);
        if (fd < 0) continue; // doesn't exist or can't open; ignore
        int locked = fd_locked_by_fcntl(fd);
        close(fd);
        if (locked) return 1;
    }
    return 0;
}

static pid_t passwd_db_lock_holder(void) {
    // Some tools lock the "lock files" (e.g. /etc/.pwd.lock), while others
    // lock the database files themselves (/etc/passwd, /etc/shadow, ...).
    // We probe both sets.
    const char* paths[] = {
        "/etc/passwd",      "/etc/shadow",      "/etc/group",      "/etc/gshadow",
        "/etc/passwd.lock", "/etc/shadow.lock", "/etc/group.lock", "/etc/gshadow.lock",
        "/etc/.pwd.lock",
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        int fd = open(paths[i], O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            // Fall back to O_RDONLY for files like /etc/shadow when running in
            // constrained environments; advisory lock queries still work.
            fd = open(paths[i], O_RDONLY | O_CLOEXEC);
            if (fd < 0) continue;
        }
        pid_t pid = lock_holder_pid_by_fcntl(fd);
        close(fd);
        if (pid > 0) return pid;
    }
    return 0; // unknown / OFD lock / no lock observed
}

static void sleep_ms(int ms) {
    if (ms <= 0) return;
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

// Serialize passwd/group DB mutations across concurrent helper invocations.
// This does not replace shadow-utils internal locks, but prevents the daemon
// from creating its own contention storms when multiple admin calls race.
static int acquire_passwddb_serial_lock(int* out_fd) {
    if (out_fd) *out_fd = -1;
    char lock_path[256];
    snprintf(lock_path, sizeof(lock_path), "%s/passwd_db.serial.lock", MCP_STATE_DIR);
    int fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", lock_path, strerror(errno));
        return -1;
    }

    // Wait up to ~30s for our own serialization lock.
    for (int attempt = 0; attempt < 60; ++attempt) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
            if (out_fd) *out_fd = fd;
            return 0;
        }
        if (errno != EWOULDBLOCK) break;
        sleep_ms(500);
    }

    fprintf(stderr, "timeout acquiring %s\n", lock_path);
    close(fd);
    return -1;
}

static void release_passwddb_serial_lock(int fd) {
    if (fd >= 0) {
        (void)flock(fd, LOCK_UN);
        close(fd);
    }
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

    int serial_fd = -1;
    if (acquire_passwddb_serial_lock(&serial_fd) != 0) return 11;

    // Retry transient failures caused by passwd DB lock contention.
    // We classify lock contention either by (a) detecting a held lock using
    // fcntl, or (b) seeing a known lock error in useradd's stderr.
    int rc = -1;
    char err[2048];
    int backoff_ms = 200;
    int last_attempt = -1;
    // Give the system a little more time (e.g. apt/dpkg triggers) before failing.
    for (int attempt = 0; attempt < 60; ++attempt) {
        last_attempt = attempt;
        rc = run_capture_stderr("/usr/sbin/useradd", a, err, sizeof(err));
        if (rc == 0) return 0;
        if (rc == 9) return 14;   // useradd: username already in use
        // Match common shadow-utils messages (English) and any "cannot lock" variant.
        int msg_looks_like_lock =
            (strstr(err, "cannot lock") != NULL) ||
            (strstr(err, "try again later") != NULL);
        int looks_like_lock =
            (rc == 1) && (passwd_db_locked() || msg_looks_like_lock);
        if (looks_like_lock) {
            if (attempt == 0) {
                fprintf(stderr,
                        "useradd: passwd db busy, retrying (up to 60 attempts)\n");
            }
            sleep_ms(backoff_ms);
            if (backoff_ms < 2000) backoff_ms *= 2;
            continue;
        }
        break;
    }

    pid_t holder = passwd_db_lock_holder();
    fprintf(stderr,
            "useradd failed after %d attempt(s) exit=%d lock_holder_pid=%ld output=%s\n",
            last_attempt + 1, rc, (long)holder, err);
    release_passwddb_serial_lock(serial_fd);
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

    int serial_fd = -1;
    if (acquire_passwddb_serial_lock(&serial_fd) != 0) return 11;
    int rc = run("/usr/sbin/userdel", a);
    release_passwddb_serial_lock(serial_fd);
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

    size_t after_id = strlen(prefix_a) + 8;

    // Per-command form: `... NOPASSWD: /<absolute-path>`. visudo -cf is the
    // authoritative validator for the trailing command spec.
    static const char path_mid[] = " ALL=(root) NOPASSWD: /";
    if (len - after_id >= strlen(path_mid) &&
        memcmp(buf + after_id, path_mid, strlen(path_mid)) == 0) {
        return 1;
    }

    // full_admin form: exact wildcard, no command path. Reserved for the
    // top-tier admin grant; visudo will accept it and the kernel will allow
    // any sudo invocation by the bound mcp_user_<shortid>.
    static const char wildcard_tail[] = " ALL=(ALL) NOPASSWD: ALL\n";
    if (len == after_id + strlen(wildcard_tail) &&
        memcmp(buf + after_id, wildcard_tail, strlen(wildcard_tail)) == 0) {
        return 1;
    }

    return 0;
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

static int cmd_install_system_admin(int argc, char** argv) {
    if (argc != 1 || !valid_shortid(argv[0])) {
        fprintf(stderr, "usage: mcp_bridge-priv install-system-admin <shortid>\n");
        return 10;
    }

    // Build the wildcard spec inline. Same shape spec_well_formed accepts.
    char spec[64];
    int n = snprintf(spec, sizeof(spec),
                     "mcp_user_%s ALL=(ALL) NOPASSWD: ALL\n", argv[0]);
    if (n <= 0 || (size_t)n >= sizeof(spec)) return 11;
    if (!spec_well_formed(spec, (size_t)n)) {
        fprintf(stderr, "internal: rendered spec failed shape check\n");
        return 13;
    }

    char tmp_path[256], final_path[256];
    snprintf(tmp_path, sizeof(tmp_path),   "%s/.mcp_system_admin.tmp", MCP_SUDOERS_DIR);
    snprintf(final_path, sizeof(final_path),"%s/mcp_system_admin",      MCP_SUDOERS_DIR);

    int wfd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0440);
    if (wfd < 0) {
        fprintf(stderr, "open %s: %s\n", tmp_path, strerror(errno));
        return 11;
    }
    ssize_t off = 0;
    while (off < n) {
        ssize_t w = write(wfd, spec + off, (size_t)(n - off));
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

    // Idempotent: rename overwrites an existing target on POSIX.
    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        fprintf(stderr, "rename %s -> %s: %s\n", tmp_path, final_path, strerror(errno));
        return 11;
    }
    return 0;
}

static int cmd_revoke_system_admin(int argc, char** argv) {
    (void)argv;
    if (argc != 0) {
        fprintf(stderr, "usage: mcp_bridge-priv revoke-system-admin\n");
        return 10;
    }
    char path[256];
    snprintf(path, sizeof(path), "%s/mcp_system_admin", MCP_SUDOERS_DIR);
    if (unlink(path) == 0) return 0;
    if (errno == ENOENT) return 0;
    fprintf(stderr, "unlink %s: %s\n", path, strerror(errno));
    return 11;
}

// mkdir + chown + chmod, idempotent on EEXIST. Returns 0 on success, -1 on err.
static int ensure_owned_dir(const char* path, uid_t uid, gid_t gid, mode_t mode) {
    if (mkdir(path, mode) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (chown(path, uid, gid) != 0) {
        fprintf(stderr, "chown %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (chmod(path, mode) != 0) {
        fprintf(stderr, "chmod %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int cmd_prepare_user_state(int argc, char** argv) {
    if (argc != 1 || !valid_shortid(argv[0])) {
        fprintf(stderr, "usage: mcp_bridge-priv prepare-user-state <shortid>\n");
        return 10;
    }
    char username[32];
    snprintf(username, sizeof(username), "mcp_user_%s", argv[0]);

    // Resolve target uid/gid via getpwnam_r.
    char buf[1024];
    struct passwd pw;
    struct passwd* result = NULL;
    int rc = getpwnam_r(username, &pw, buf, sizeof(buf), &result);
    if (rc != 0 || !result) {
        fprintf(stderr, "getpwnam_r %s: %s\n", username,
                rc != 0 ? strerror(rc) : "not found");
        return 12;
    }
    uid_t uid = pw.pw_uid;
    gid_t gid = pw.pw_gid;

    // Ensure top-level users_state dir exists (root:mcp 0755 — but we may not
    // know the mcp gid here, so leave existing perms intact if it exists).
    if (mkdir(MCP_USERS_STATE_DIR, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s\n", MCP_USERS_STATE_DIR, strerror(errno));
        return 11;
    }

    char user_dir[256], crons_dir[256];
    snprintf(user_dir,  sizeof(user_dir),  "%s/%s",        MCP_USERS_STATE_DIR, username);
    snprintf(crons_dir, sizeof(crons_dir), "%s/%s/crons",  MCP_USERS_STATE_DIR, username);

    if (ensure_owned_dir(user_dir,  uid, gid, 0700) != 0) return 11;
    if (ensure_owned_dir(crons_dir, uid, gid, 0700) != 0) return 11;
    return 0;
}

static int cmd_cleanup_user_state(int argc, char** argv) {
    if (argc != 1 || !valid_shortid(argv[0])) {
        fprintf(stderr, "usage: mcp_bridge-priv cleanup-user-state <shortid>\n");
        return 10;
    }
    char user_dir[256];
    snprintf(user_dir, sizeof(user_dir), "%s/mcp_user_%s",
             MCP_USERS_STATE_DIR, argv[0]);

    // Idempotent: if it doesn't exist, we're done.
    struct stat st;
    if (lstat(user_dir, &st) != 0) {
        if (errno == ENOENT) return 0;
        fprintf(stderr, "lstat %s: %s\n", user_dir, strerror(errno));
        return 11;
    }

    char* a[] = {"rm", "-rf", "--", user_dir, NULL};
    int rc = run("/usr/bin/rm", a);
    if (rc == 0) return 0;
    fprintf(stderr, "rm -rf %s exit=%d\n", user_dir, rc);
    return 11;
}

static int b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Decode standard base64 into dst. Returns number of bytes written or -1.
static ssize_t base64_decode(const char* in, unsigned char* dst, size_t dst_sz) {
    if (!in || !dst) return -1;
    size_t out = 0;
    int quad[4];
    int q = 0;
    for (const unsigned char* p = (const unsigned char*)in; *p; ++p) {
        unsigned char c = *p;
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (c == '=') {
            quad[q++] = -2; // padding
        } else {
            int v = b64_val(c);
            if (v < 0) return -1;
            quad[q++] = v;
        }
        if (q == 4) {
            if (quad[0] < 0 || quad[1] < 0) return -1;
            unsigned b0 = ((unsigned)quad[0] << 2) | ((unsigned)quad[1] >> 4);
            if (out + 1 > dst_sz) return -1;
            dst[out++] = (unsigned char)b0;
            if (quad[2] == -2) { q = 0; break; }
            if (quad[2] < 0) return -1;
            unsigned b1 = (((unsigned)quad[1] & 0x0f) << 4) | ((unsigned)quad[2] >> 2);
            if (out + 1 > dst_sz) return -1;
            dst[out++] = (unsigned char)b1;
            if (quad[3] == -2) { q = 0; break; }
            if (quad[3] < 0) return -1;
            unsigned b2 = (((unsigned)quad[2] & 0x03) << 6) | (unsigned)quad[3];
            if (out + 1 > dst_sz) return -1;
            dst[out++] = (unsigned char)b2;
            q = 0;
        }
    }
    if (q != 0) return -1; // incomplete quartet
    return (ssize_t)out;
}

static int cmd_write_runtime(int argc, char** argv) {
    if (argc != 2 || !valid_shortid(argv[0]) || !argv[1] || argv[1][0] == '\0') {
        fprintf(stderr, "usage: mcp_bridge-priv write-runtime <shortid> <base64>\n");
        return 10;
    }
    char username[32];
    snprintf(username, sizeof(username), "mcp_user_%s", argv[0]);

    // Resolve target uid/gid via getpwnam_r.
    char buf[1024];
    struct passwd pw;
    struct passwd* result = NULL;
    int rc = getpwnam_r(username, &pw, buf, sizeof(buf), &result);
    if (rc != 0 || !result) {
        fprintf(stderr, "getpwnam_r %s: %s\n", username,
                rc != 0 ? strerror(rc) : "not found");
        return 12;
    }
    uid_t uid = pw.pw_uid;
    gid_t gid = pw.pw_gid;

    // Ensure user state dirs exist and are owned by the target user.
    char user_dir[256];
    snprintf(user_dir, sizeof(user_dir), "%s/%s", MCP_USERS_STATE_DIR, username);
    if (ensure_owned_dir(user_dir, uid, gid, 0700) != 0) return 11;

    char runtime_path[512], tmp_path[512];
    snprintf(runtime_path, sizeof(runtime_path), "%s/runtime.json", user_dir);
    snprintf(tmp_path, sizeof(tmp_path), "%s/runtime.json.tmp", user_dir);

    unsigned char decoded[4096];
    ssize_t n = base64_decode(argv[1], decoded, sizeof(decoded));
    if (n < 0) {
        fprintf(stderr, "base64 decode failed\n");
        return 11;
    }

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", tmp_path, strerror(errno));
        return 11;
    }
    ssize_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, decoded + off, (size_t)(n - off));
        if (w < 0) { close(fd); unlink(tmp_path); return 11; }
        off += w;
    }
    if (fsync(fd) != 0) { close(fd); unlink(tmp_path); return 11; }
    close(fd);

    if (chown(tmp_path, uid, gid) != 0) {
        unlink(tmp_path);
        fprintf(stderr, "chown %s: %s\n", tmp_path, strerror(errno));
        return 11;
    }
    if (chmod(tmp_path, 0600) != 0) {
        unlink(tmp_path);
        fprintf(stderr, "chmod %s: %s\n", tmp_path, strerror(errno));
        return 11;
    }
    if (rename(tmp_path, runtime_path) != 0) {
        unlink(tmp_path);
        fprintf(stderr, "rename %s -> %s: %s\n", tmp_path, runtime_path, strerror(errno));
        return 11;
    }
    return 0;
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

    // The setuid bit (mode 4750 root:mcp) gives us euid=0 but leaves the
    // real uid as the daemon's (`mcp`). Shadow-utils (useradd/usermod/...)
    // check getuid()==0 and exit with "Permission denied" otherwise, which
    // surfaces as a "cannot lock /etc/passwd" retry loop. Promote real and
    // saved uid to 0 so exec'd children inherit a real uid of 0.
    if (geteuid() != 0) {
        fprintf(stderr,
                "mcp_bridge-priv: not effective-root (missing setuid bit? "
                "expected mode 4750 root:mcp; got euid=%d)\n", geteuid());
        return 11;
    }
    if (setuid(0) != 0) {
        fprintf(stderr, "setuid(0): %s\n", strerror(errno));
        return 11;
    }

    if (strcmp(argv[1], "useradd") == 0)              return cmd_useradd(argc - 2, argv + 2);
    if (strcmp(argv[1], "userdel") == 0)              return cmd_userdel(argc - 2, argv + 2);
    if (strcmp(argv[1], "install-grant") == 0)        return cmd_install_grant(argc - 2, argv + 2);
    if (strcmp(argv[1], "revoke-grant") == 0)         return cmd_revoke_grant(argc - 2, argv + 2);
    if (strcmp(argv[1], "install-system-admin") == 0) return cmd_install_system_admin(argc - 2, argv + 2);
    if (strcmp(argv[1], "revoke-system-admin") == 0)  return cmd_revoke_system_admin(argc - 2, argv + 2);
    if (strcmp(argv[1], "prepare-user-state") == 0)   return cmd_prepare_user_state(argc - 2, argv + 2);
    if (strcmp(argv[1], "cleanup-user-state") == 0)   return cmd_cleanup_user_state(argc - 2, argv + 2);
    if (strcmp(argv[1], "write-runtime") == 0)        return cmd_write_runtime(argc - 2, argv + 2);

    fprintf(stderr, "unknown subcommand: %s\n", argv[1]);
    return 10;
}
