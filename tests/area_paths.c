/*
 * sbx_test, area "paths": path calls: the broker protocol harness, fail-closed, FIFOs, PATHOPS, WATCH, unbrokered, passthrough and listing, fewer round trips.
 * Included by tests/sbx_test.c, one translation unit with the harness (tests/sbx_test.h);
 * SBX_TEST_AREA=paths runs this area alone (#767).
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */

/* ---- SBX_LOCK_PATHOPS and SBX_LOCK_INOTIFY: link, symlink and truncate through the broker, marks allowed. ---- */

/*
 * The broker's wire protocol, driven directly. A test (unconfined) builds a
 * request and sends it to a broker thread, then reads the reply, so a
 * malformed or hostile message can be tested without a confined child making
 * it -- the handler would only ever send well-formed ones. The broker learns
 * the sender's pid from SO_PASSCRED, which it sets itself. The first
 * descriptor is the socket the broker answers on; any others follow it.
 * Returns the reply's result, or -EIO if no reply arrived.
 */
/* Sends one request message with the given descriptors (fds[0] is the answer socket). Returns the sendmsg result. */
static ssize_t broker_send(int to, const struct sbx_request *request, const void *body, size_t body_len,
                           const int *fds, int nfds, int flags) {
    struct iovec parts[2] = {{(void *) request, sizeof(*request)}, {(void *) body, body_len}};
    union {
        char buffer[CMSG_SPACE(sizeof(int) * 4)];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = parts;
    message.msg_iovlen = body_len ? 2 : 1;
    message.msg_control = control.buffer;
    message.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);
    struct cmsghdr *cm = CMSG_FIRSTHDR(&message);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
    memcpy(CMSG_DATA(cm), fds, sizeof(int) * nfds);
    return sendmsg(to, &message, flags);
}

static int64_t broker_request(int to, const struct sbx_request *request, const void *body, size_t body_len,
                              const int *extra, int extra_count) {
    int answer[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, answer) != 0) return -EIO;
    struct timeval timeout = {10, 0};
    setsockopt(answer[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int fds[4];
    int n = 0;
    fds[n++] = answer[1];
    for (int i = 0; i < extra_count && n < 4; i++) fds[n++] = extra[i];
    int64_t result = -EIO;
    if (broker_send(to, request, body, body_len, fds, n, MSG_NOSIGNAL) >= 0) {
        struct sbx_reply header;
        char data[512];
        struct iovec rparts[2] = {{&header, sizeof(header)}, {data, sizeof(data)}};
        struct msghdr rmsg;
        memset(&rmsg, 0, sizeof(rmsg));
        rmsg.msg_iov = rparts;
        rmsg.msg_iovlen = 2;
        ssize_t got = recvmsg(answer[0], &rmsg, 0);
        if (got >= (ssize_t) sizeof(header)) result = header.result;
    }
    close(answer[0]);
    close(answer[1]);
    return result;
}

/*
 * A client that hands the broker an answer socket whose buffer is already
 * full must not wedge the broker's one serve thread. The broker replies
 * non-blocking, drops that reply, and keeps serving. The wedge here is a
 * socketpair whose receive side we fill before handing its other end over;
 * the broker's reply to it cannot be delivered. A fresh request afterwards
 * must still be answered -- if it is not (a blocking reply), broker_request's
 * receive timeout turns the wedge into a failed check rather than a hang.
 */
static int reply_wedge_check(void) {
    int before = failures;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    char path[400];
    int plen = snprintf(path, sizeof(path), "%s/data.txt", game);
    struct sbx_request stat_req = {.version = SBX_PROTOCOL_VERSION, .op = SBX_STAT, .path_len = (uint32_t) plen};

    int wedge[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, wedge) != 0) return 1;
    int small = 1024;
    setsockopt(wedge[0], SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
    setsockopt(wedge[1], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    /* Fill the receive side, so the broker's reply to wedge[1] can never be delivered. */
    char junk[256];
    memset(junk, 0, sizeof(junk));
    while (send(wedge[1], junk, sizeof(junk), MSG_DONTWAIT) > 0) { /* until EAGAIN */ }
    EXPECT(broker_send(pair[1], &stat_req, path, (size_t) plen, &wedge[1], 1, MSG_NOSIGNAL) >= 0,
           "reply wedge: the request with a full answer socket is sent");

    /* The broker must have survived it: a fresh request is still answered. */
    EXPECT(broker_request(pair[1], &stat_req, path, (size_t) plen, NULL, 0) == 0,
           "reply wedge: the broker keeps serving when an answer socket is full");

    close(wedge[0]);
    close(wedge[1]);
    close(pair[1]);
    return failures != before;
}

/*
 * Runs in a forked child: locks down with the broker's peer already closed, so
 * the first brokered call finds the broker gone. With SBX_LOCK_FAIL_CLOSED the
 * process must not reach the return (the call ends it); without it the call
 * answers EIO and the child returns 0. Other exit codes report where it went
 * wrong. An alarm keeps a hang from wedging the run.
 */
static int fail_closed_child(int broker_fd, unsigned flags) {
    alarm(20);
    struct sbx_lockdown_options options = {.flags = flags};
    if (sbx_lockdown(broker_fd, &options) != 0) return 55;
    errno = 0;
    int fd = open("/sandbox-fail-closed-probe", O_RDONLY);  /* any brokered path op; the broker is gone */
    if (fd >= 0) { close(fd); return 60; }
    return errno == EIO ? 0 : 61;
}

/* A-21: a brokered call whose broker has gone ends the process under SBX_LOCK_FAIL_CLOSED, and answers EIO without it. */
static int fail_closed_check(void) {
    int before = failures;
    for (int strict = 0; strict < 2; strict++) {
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
        fflush(stdout);
        pid_t child = fork();
        if (child == 0) {
            close(pair[0]);  /* nothing serves the broker; with the parent's copy closed too, its peer is gone */
            _exit(fail_closed_child(pair[1], strict ? SBX_LOCK_FAIL_CLOSED : 0));
        }
        close(pair[0]);
        close(pair[1]);
        int status = 0;
        waitpid(child, &status, 0);
        if (strict) {
            EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 120,
                   "fail closed: a brokered call after the broker is gone ends the process");
        } else {
            EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                   "fail closed control: without the flag the call answers EIO and the process continues");
        }
        if (!WIFEXITED(status)) printf("info fail closed (strict=%d): child did not exit normally\n", strict);
        else if ((strict && WEXITSTATUS(status) != 120) || (!strict && WEXITSTATUS(status) != 0))
            printf("info fail closed (strict=%d): child exited %d\n", strict, WEXITSTATUS(status));
    }
    return failures != before;
}

/* The broker refuses malformed requests rather than misreading or dropping them. */
static int harness_check(void) {
    int before = failures;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    int client = pair[1];
    char path[400];
    int plen = snprintf(path, sizeof(path), "%s/data.txt", game);

    /* Sanity: a well-formed stat of a granted path answers 0, proving the harness itself works. */
    struct sbx_request good = {.version = SBX_PROTOCOL_VERSION, .op = SBX_STAT, .path_len = (uint32_t) plen};
    EXPECT(broker_request(client, &good, path, (size_t) plen, NULL, 0) == 0, "harness: a well-formed stat answers 0");

    /*
     * dirfd_sent is a count of 0 or 1. A request claiming 2 (with two extra
     * descriptors so the fd count still adds up) must be refused, not read as
     * if one of them were the directory.
     */
    int dir = open(game, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int two[2] = {dir, dir};
    struct sbx_request bad_dirfd = {.version = SBX_PROTOCOL_VERSION, .op = SBX_STAT,
                                    .path_len = (uint32_t) plen, .dirfd_sent = 2};
    EXPECT(broker_request(client, &bad_dirfd, path, (size_t) plen, two, 2) == -EINVAL,
           "harness: dirfd_sent > 1 is refused with EINVAL");
    if (dir >= 0) close(dir);

    /* A wrong protocol version is refused. */
    struct sbx_request bad_version = {.version = SBX_PROTOCOL_VERSION + 1, .op = SBX_STAT, .path_len = (uint32_t) plen};
    EXPECT(broker_request(client, &bad_version, path, (size_t) plen, NULL, 0) == -EINVAL,
           "harness: a wrong protocol version is refused");

    /* A zero-length path is refused. */
    struct sbx_request empty = {.version = SBX_PROTOCOL_VERSION, .op = SBX_STAT, .path_len = 0};
    EXPECT(broker_request(client, &empty, "", 0, NULL, 0) == -EINVAL, "harness: a zero-length path is refused");

    /*
     * A learn record's "would" is an errno the broker negates; INT32_MIN would
     * make that negation undefined (the fuzzer found it). An out-of-range value
     * is refused, not negated.
     */
    struct sbx_learn_record bad_learn;
    memset(&bad_learn, 0, sizeof(bad_learn));
    bad_learn.nr = __NR_openat;
    bad_learn.would = INT32_MIN;
    struct sbx_request learn_req = {.version = SBX_PROTOCOL_VERSION, .op = SBX_LEARN};
    EXPECT(broker_request(client, &learn_req, &bad_learn, sizeof(bad_learn), NULL, 0) == -EINVAL,
           "harness: a learn record with an out-of-range errno is refused, not negated");

    close(client);
    return failures != before;
}

/*
 * A malformed request that still carried an answer socket is answered with
 * EINVAL, not dropped silently (which would leave the client hanging). The
 * malformation here is more descriptors than the broker's control buffer
 * holds, so the kernel truncates them (MSG_CTRUNC) and the broker does not
 * serve the request. broker_request's receive timeout turns a silent drop (a
 * regression) into a failed check rather than a hang.
 */
static int einval_drop_check(void) {
    int before = failures;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    char path[400];
    int plen = snprintf(path, sizeof(path), "%s/data.txt", game);
    struct sbx_request req = {.version = SBX_PROTOCOL_VERSION, .op = SBX_STAT, .path_len = (uint32_t) plen};
    int spare = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (spare < 0) { close(pair[1]); return 0; }
    int extra[3] = {spare, spare, spare};
    EXPECT(broker_request(pair[1], &req, path, (size_t) plen, extra, 3) == -EINVAL,
           "einval: a request whose descriptors the kernel truncated is answered, not dropped");
    close(spare);
    close(pair[1]);
    return failures != before;
}

/*
 * A FIFO in a writable rule must not stall the broker. The broker opens it
 * non-blocking, so a plain open of a FIFO with no writer returns a descriptor
 * instead of holding the broker's one serve thread. An alarm turns a stall
 * (a regression) into a failed child rather than a hung run.
 */
static int fifo_check(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    char fifo[400], regular[400];
    snprintf(fifo, sizeof(fifo), "%s/f-fifo", save);
    snprintf(regular, sizeof(regular), "%s/f-regular", save);
    unlink(fifo);
    unlink(regular);
    int made = mkfifo(fifo, 0600);
    write_file(regular, "ok");
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        alarm(20);
        struct sbx_lockdown_options options = {0};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "fifo: lockdown");
        if (locked != 0) _exit(1);
        if (made == 0) {
            int fd = open(fifo, O_RDONLY);
            EXPECT(fd >= 0, "fifo: a FIFO in a rule opens without stalling the broker");
            if (fd >= 0) close(fd);
            /* Non-blocking at the broker: O_WRONLY with no reader is ENXIO, where unconfined it would wait. */
            errno = 0;
            EXPECT(open(fifo, O_WRONLY) < 0 && errno == ENXIO, "fifo: O_WRONLY with no reader answers ENXIO, not a stall");
        }
        int rf = open(regular, O_RDONLY);
        EXPECT(rf >= 0, "fifo: an ordinary file still opens");
        if (rf >= 0) close(rf);
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    unlink(fifo);
    unlink(regular);
    if (made != 0) printf("skip fifo: the host refused mkfifo in the writable folder\n");
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

static int pathops_check(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    char source[400], hard[400], stolen[400], from_secret[400], sym[400], game_sym[400], followed[400];
    char data[400], key[400];
    snprintf(source, sizeof(source), "%s/p-source", save);
    snprintf(hard, sizeof(hard), "%s/p-hard", save);
    snprintf(stolen, sizeof(stolen), "%s/p-stolen", save);
    snprintf(from_secret, sizeof(from_secret), "%s/p-secret", save);
    snprintf(sym, sizeof(sym), "%s/p-sym", save);
    snprintf(game_sym, sizeof(game_sym), "%s/p-sym", game);
    snprintf(followed, sizeof(followed), "%s/p-followed", save);
    snprintf(data, sizeof(data), "%s/data.txt", game);
    snprintf(key, sizeof(key), "%s/key", secret);
    /* The control: some hosts refuse hard links to everyone (Android's SELinux for the shell and apps). */
    write_file(source, "probe");
    int host_links = link(source, hard) == 0;
    int link_error = errno;
    unlink(hard);
    unlink(source);
    if (!host_links) printf("skip pathops: link between writable names (the host refuses it unconfined: %s)\n", strerror(link_error));
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_PATHOPS | SBX_LOCK_INOTIFY};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "pathops: lockdown");
        if (locked != 0) _exit(1);
        int fd = open(source, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
        EXPECT(fd >= 0 && write(fd, "four", 4) == 4, "pathops: a file in the writable rule");
        if (fd >= 0) close(fd);
        struct stat a, b;
        if (host_links) {
            EXPECT(link(source, hard) == 0, "pathops: link between two writable names");
            EXPECT(stat(source, &a) == 0 && stat(hard, &b) == 0 && a.st_ino == b.st_ino, "pathops: and both name one file");
        }
        errno = 0;
        EXPECT(refused(link(data, stolen)), "pathops: link of a read-only file into a writable rule is refused");
        errno = 0;
        EXPECT(refused(link(key, from_secret)), "pathops: link of a file outside the rules is refused");
        EXPECT(symlink("../secret/key", sym) == 0, "pathops: symlink in the writable rule, target stored as given");
        char target[64] = {0};
        EXPECT(readlink(sym, target, sizeof(target) - 1) > 0 && strcmp(target, "../secret/key") == 0,
               "pathops: readlink gives the target back unchanged");
        errno = 0;
        EXPECT(refused(open(sym, O_RDONLY)), "pathops: following it out of the rules is refused");
        errno = 0;
        EXPECT(refused(linkat(AT_FDCWD, sym, AT_FDCWD, followed, AT_SYMLINK_FOLLOW)),
               "pathops: linkat following it out of the rules is refused");
        errno = 0;
        EXPECT(refused(symlink("anything", game_sym)), "pathops: symlink in a read-only rule is refused");
        EXPECT(truncate(source, 2) == 0 && stat(source, &a) == 0 && a.st_size == 2, "pathops: truncate in the writable rule");
        errno = 0;
        EXPECT(refused(truncate(data, 0)), "pathops: truncate in a read-only rule is refused");
        errno = 0;
        EXPECT(refused(truncate(key, 0)), "pathops: truncate outside the rules is refused");
        int watcher = inotify_init1(IN_CLOEXEC);
        EXPECT(watcher >= 0 && inotify_add_watch(watcher, save, IN_CREATE) >= 0, "inotify: a mark with SBX_LOCK_INOTIFY");
        if (watcher >= 0) close(watcher);
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    char content[16] = {0};
    FILE *f = fopen(key, "r");
    if (f) {
        if (!fgets(content, sizeof(content), f)) content[0] = 0;
        fclose(f);
    }
    int failed = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    if (strcmp(content, "secret") != 0) {
        printf("FAIL pathops: the file outside the rules was changed\n");
        failed = 1;
    }
    unlink(source);
    unlink(hard);
    unlink(sym);
    return failed;
}

/* ---- SBX_LOCK_WATCH: inotify marks decided and added by the broker. ---- */

/* The mask the kernel holds for watch wd on inotify descriptor fd, from /proc/self/fdinfo; 0 when it is not there. */
static unsigned watch_mask(int fd, int wd) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned mask = 0;
    while (fgets(line, sizeof(line), f)) {
        int found;
        const char *m = strstr(line, " mask:");
        if (sscanf(line, "inotify wd:%x", (unsigned *) &found) == 1 && found == wd && m) {
            mask = (unsigned) strtoul(m + 6, NULL, 16);
        }
    }
    fclose(f);
    return mask;
}

static int watch_check(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    char hidden[400], visible[400], made[500], link_out[400], data[400];
    snprintf(hidden, sizeof(hidden), "%s/w-hidden", game);
    snprintf(visible, sizeof(visible), "%s/w-visible", save);
    snprintf(made, sizeof(made), "%s/w-made", visible);
    snprintf(link_out, sizeof(link_out), "%s/w-link", save);
    snprintf(data, sizeof(data), "%s/data.txt", game);
    mkdir(hidden, 0700);
    mkdir(visible, 0700);
    unlink(link_out);
    if (symlink(secret, link_out) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    sbx_policy_add(policy, hidden, SBX_DENY);
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_WATCH | SBX_LOCK_INOTIFY};
        EXPECT(sbx_lockdown(pair[1], &options) == -EINVAL, "watch: not with SBX_LOCK_INOTIFY");
        options.flags = SBX_LOCK_WATCH | SBX_LOCK_UNBROKERED;
        EXPECT(sbx_lockdown(pair[1], &options) == -EINVAL, "watch: not without the broker");
        options.flags = SBX_LOCK_WATCH;
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "watch: lockdown");
        if (locked != 0) _exit(1);
        int fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
        EXPECT(fd >= 0, "watch: an inotify descriptor");

        int wd = inotify_add_watch(fd, visible, IN_CREATE | IN_DELETE);
        EXPECT(wd >= 0, "watch: a folder whose names are all readable");
        unsigned mask = wd >= 0 ? watch_mask(fd, wd) : 0;
        EXPECT((mask & (IN_CREATE | IN_DELETE)) == (IN_CREATE | IN_DELETE), "watch: keeps the events asked for");
        int made_fd = open(made, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
        if (made_fd >= 0) close(made_fd);
        char events[4096];
        ssize_t got = read(fd, events, sizeof(events));
        const struct inotify_event *event = (const struct inotify_event *) events;
        EXPECT(got >= (ssize_t) sizeof(*event) && event->wd == wd && (event->mask & IN_CREATE) && event->len > 0 &&
                   strcmp(event->name, "w-made") == 0,
               "watch: the event names the file made there");

        wd = inotify_add_watch(fd, game, IN_CREATE | IN_DELETE_SELF);
        EXPECT(wd >= 0, "watch: a folder holding a name it may not read is still watched");
        mask = wd >= 0 ? watch_mask(fd, wd) : 0;
        EXPECT(!(mask & IN_CREATE) && (mask & IN_DELETE_SELF), "watch: but only for the folder's own events");
        wd = inotify_add_watch(fd, game, IN_CREATE);
        mask = wd >= 0 ? watch_mask(fd, wd) : 0;
        EXPECT(wd >= 0 && !(mask & IN_CREATE) && (mask & IN_DELETE_SELF),
               "watch: one asking only for named events watches for the folder's deletion");

        EXPECT(inotify_add_watch(fd, data, IN_MODIFY) >= 0, "watch: a readable file");
        errno = 0;
        EXPECT(refused(inotify_add_watch(fd, secret, IN_CREATE)), "watch: a folder outside the rules is refused");
        errno = 0;
        EXPECT(refused(inotify_add_watch(fd, hidden, IN_CREATE)), "watch: a folder a narrower rule denies is refused");
        errno = 0;
        EXPECT(refused(inotify_add_watch(fd, link_out, IN_CREATE)), "watch: a link out of the rules is refused");
        EXPECT(inotify_add_watch(fd, link_out, IN_ATTRIB | IN_DONT_FOLLOW) >= 0,
               "watch: with IN_DONT_FOLLOW, the link itself is watched");
        errno = 0;
        EXPECT(inotify_add_watch(fd, save, IN_ISDIR | IN_CREATE) < 0 && errno == EINVAL,
               "watch: a flag outside the standard ones is refused");
        int not_inotify[2];
        errno = 0;
        EXPECT(pipe(not_inotify) == 0 && inotify_add_watch(not_inotify[0], save, IN_CREATE) < 0 && errno == EINVAL,
               "watch: a descriptor that is not inotify is refused");
        EXPECT(chdir(save) == 0 && inotify_add_watch(fd, "w-visible", IN_CREATE) >= 0, "watch: a relative path");
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    unlink(made);
    rmdir(visible);
    rmdir(hidden);
    unlink(link_out);
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

/* ---- Unbrokered: paths go to the kernel, the rest of the wall stands. ---- */

static int unbrokered_check(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_UNBROKERED | SBX_LOCK_LOG_SOCKET};
        int locked = sbx_lockdown(-1, &options);
        errno = -locked;
        EXPECT(locked == 0, "unbrokered lockdown without a broker");
        if (locked != 0) _exit(1);
        char path[400];
        snprintf(path, sizeof(path), "%s/key", secret);
        int fd = open(path, O_RDONLY);
        EXPECT(fd >= 0, "unbrokered: paths go to the kernel");
        if (fd >= 0) close(fd);
        char buffer[512];
        EXPECT(getcwd(buffer, sizeof(buffer)) != NULL, "unbrokered: getcwd is the kernel's");
        errno = 0;
        EXPECT(refused(socket(AF_INET, SOCK_STREAM, 0)), "unbrokered: socket(AF_INET) refused");
        int log_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
        EXPECT(log_socket >= 0, "unbrokered: a Unix datagram socket for the log");
        if (log_socket >= 0) close(log_socket);
        errno = 0;
        EXPECT(a_exec() == EACCES, "unbrokered: execve refused");
        errno = 0;
        EXPECT(kill(getppid(), 0) < 0 && errno == EPERM, "unbrokered: a signal to the parent refused");
        errno = 0;
        EXPECT(a_unshare() == EPERM, "unbrokered: unshare refused");
        _exit(failures ? 1 : 0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* ---- Passthrough: claimed folders through the broker, every other path to the kernel, local files. ---- */

static int read_word(int fd, char *out, size_t size) {
    ssize_t n = read(fd, out, size - 1);
    if (n < 0) n = 0;
    out[n] = '\0';
    return (int) n;
}

static int passthrough_check(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    sbx_policy_alias(policy, "/sandbox-test/data", save);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    char real_game[PATH_MAX];
    if (!realpath(game, real_game)) return 1;
    char local_path[400];
    snprintf(local_path, sizeof(local_path), "%s/local.txt", root);
    write_file(local_path, "local");
    char rw_seed[500];
    snprintf(rw_seed, sizeof(rw_seed), "%s/rw.txt", root);
    write_file(rw_seed, "old contents");
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        /* The broker's folders: an alias, the real folder it names, and one with no rule at all. */
        const char *claims[] = {"/sandbox-test", save, secret};
        struct sbx_lockdown_options options = {
            .flags = SBX_LOCK_PASSTHROUGH | SBX_LOCK_LOG_SOCKET, .claims = claims, .claim_count = 3};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "passthrough lockdown");
        if (locked != 0) _exit(1);
        char path[600], word[16];

        snprintf(path, sizeof(path), "%s/data.txt", game);
        int fd = open(path, O_RDONLY);
        EXPECT(fd >= 0, "passthrough: an unclaimed path goes to the kernel (no rule needed)");
        if (fd >= 0) {
            read_word(fd, word, sizeof(word));
            EXPECT(strcmp(word, "hello") == 0, "passthrough: and reads");
            close(fd);
        }
        struct stat st;
        EXPECT(stat("/proc/self/status", &st) == 0, "passthrough: the process's own /proc from the kernel");
        char target[512];
        EXPECT(readlink("/proc/self/exe", target, sizeof(target)) > 0, "passthrough: readlink from the kernel");
        snprintf(path, sizeof(path), "%s/key", secret);
        errno = 0;
        EXPECT(refused(open(path, O_RDONLY)), "passthrough: a claimed path the broker has no rule for is refused");
        /*
         * Review A-06: the filter binds the handler's own passthrough path ops to its gateway
         * address, not to the PASS_DIRFD sentinel in the directory argument, which a worker could
         * forge. A worker that issues openat with that sentinel from its own code (not the gateway)
         * on this claimed-but-unruled absolute path must still trap to the broker and be refused --
         * not reach the kernel, where the file (it exists on disk) would open. PASS_DIRFD is private
         * to lockdown.c; -0x5b1 is its value.
         */
        errno = 0;
        long forged = syscall(__NR_openat, -0x5b1, path, O_RDONLY, 0);
        EXPECT(forged < 0 && errno == EACCES,
               "passthrough: a worker's forged PASS_DIRFD openat is still brokered, not kernel-direct (A-06)");
        if (forged >= 0) close((int) forged);

        fd = open("/sandbox-test/data/p.txt", O_CREAT | O_WRONLY | O_TRUNC, 0600);
        EXPECT(fd >= 0, "passthrough: a claimed alias goes to the broker and creates a file");
        if (fd >= 0) {
            EXPECT(write(fd, "put", 3) == 3, "passthrough: writes through the brokered descriptor");
            close(fd);
        }
        snprintf(path, sizeof(path), "%s/p.txt", save);
        fd = open(path, O_RDONLY);
        EXPECT(fd >= 0, "passthrough: the real claimed folder holds it");
        if (fd >= 0) {
            read_word(fd, word, sizeof(word));
            EXPECT(strcmp(word, "put") == 0, "passthrough: with what was written");
            close(fd);
        }

        /* chmod and utimensat: a claimed path goes to the broker, any other to the kernel. */
        EXPECT(chmod("/sandbox-test/data/p.txt", 0640) == 0, "passthrough: chmod of a claimed alias");
        snprintf(path, sizeof(path), "%s/p.txt", save);
        EXPECT(stat(path, &st) == 0 && (st.st_mode & 0777) == 0640, "passthrough: the real file has the mode");
        EXPECT(fchmodat(AT_FDCWD, "/sandbox-test/data/p.txt", 04755, 0) == 0 && stat(path, &st) == 0 &&
                   (st.st_mode & 07777) == 0755,
               "passthrough: the broker keeps permission bits only");
        struct timespec times[2] = {{1000, 0}, {2000, 0}};
        EXPECT(utimensat(AT_FDCWD, "/sandbox-test/data/p.txt", times, 0) == 0, "passthrough: utimensat of a claimed alias");
        EXPECT(stat(path, &st) == 0 && st.st_mtime == 2000 && st.st_atime == 1000, "passthrough: the real file has the times");
        EXPECT(utimensat(AT_FDCWD, "/sandbox-test/data/p.txt", NULL, 0) == 0 && stat(path, &st) == 0 && st.st_mtime > 2000,
               "passthrough: utimensat to now");
        fd = open("/sandbox-test/data/p.txt", O_RDONLY);
        EXPECT(fd >= 0 && futimens(fd, times) == 0, "passthrough: futimens on a descriptor");
        if (fd >= 0) close(fd);
        snprintf(path, sizeof(path), "%s/data.txt", game);
        EXPECT(chmod(path, 0644) == 0, "passthrough: chmod of an unclaimed path from the kernel");
        snprintf(path, sizeof(path), "%s/key", secret);
        errno = 0;
        EXPECT(refused(chmod(path, 0666)), "passthrough: chmod of a claimed path with no rule is refused");
        errno = 0;
        EXPECT(refused(utimensat(AT_FDCWD, path, NULL, 0)), "passthrough: utimensat of a claimed path with no rule is refused");

        /* Listing: getdents64 traps in passthrough; the handler's own call lists what the kernel lets it. */
        DIR *listing = opendir("/sandbox-test/data");
        int seen = 0;
        if (listing) {
            struct dirent *entry;
            while ((entry = readdir(listing)) != NULL) seen |= strcmp(entry->d_name, "p.txt") == 0;
            rewinddir(listing);
            int again = 0;
            while ((entry = readdir(listing)) != NULL) again |= strcmp(entry->d_name, "p.txt") == 0;
            seen &= again;
            closedir(listing);
        }
        EXPECT(seen, "passthrough: a claimed folder lists, and lists again after rewinddir");
        listing = opendir(game);
        seen = 0;
        if (listing) {
            struct dirent *entry;
            while ((entry = readdir(listing)) != NULL) seen |= strcmp(entry->d_name, "data.txt") == 0;
            closedir(listing);
        }
        EXPECT(seen, "passthrough: an unclaimed folder lists");

        EXPECT(chdir(game) == 0, "passthrough: chdir into an unclaimed folder");
        fd = open("data.txt", O_RDONLY);
        EXPECT(fd >= 0, "passthrough: a relative path from there goes to the kernel");
        if (fd >= 0) close(fd);
        char cwd[PATH_MAX];
        EXPECT(getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, real_game) == 0, "passthrough: getcwd names it");
        EXPECT(chdir("/sandbox-test/data") == 0, "passthrough: chdir into a claimed folder");
        fd = open("p.txt", O_RDONLY);
        EXPECT(fd >= 0, "passthrough: a relative path from there goes to the broker");
        if (fd >= 0) close(fd);
        int dir = open(game, O_RDONLY | O_DIRECTORY);
        EXPECT(dir >= 0, "passthrough: an unclaimed folder opens as a directory");
        if (dir >= 0) {
            fd = openat(dir, "data.txt", O_RDONLY);
            EXPECT(fd >= 0, "passthrough: openat relative to it");
            if (fd >= 0) close(fd);
            close(dir);
        }
        struct statfs fs;
        EXPECT(statfs(game, &fs) == 0, "passthrough: statfs from the kernel");

        /* A local file, given after the lockdown under a name nothing else has. */
        fd = open(local_path, O_RDONLY);
        int added = fd >= 0 ? sbx_local_add("/sandbox-local/lib.so", fd) : -EBADF;
        errno = -added;
        EXPECT(added == 0, "sbx_local_add after lockdown");
        fd = open("/sandbox-local/lib.so", O_RDONLY);
        EXPECT(fd >= 0, "a local file opens by its name");
        if (fd >= 0) {
            read_word(fd, word, sizeof(word));
            EXPECT(strcmp(word, "local") == 0, "and reads from its start");
            close(fd);
        }
        EXPECT(stat("/sandbox-local/lib.so", &st) == 0 && st.st_size == 5, "stat of a local file");
        EXPECT(access("/sandbox-local/lib.so", R_OK) == 0, "access of a local file");
        errno = 0;
        EXPECT(refused(access("/sandbox-local/lib.so", W_OK)), "a local file is not writable (access)");
        errno = 0;
        EXPECT(refused(open("/sandbox-local/lib.so", O_RDWR)), "a local file is not writable (open)");

        /* A writable local file (sbx_local_add_mode), as droidtop hands over a file it opened for writing. */
        char rw_path[500];
        snprintf(rw_path, sizeof(rw_path), "%s/rw.txt", root);
        int rw = open(rw_path, O_RDWR);
        added = rw >= 0 ? sbx_local_add_mode("/sandbox-local/rw.txt", rw, SBX_READ | SBX_WRITE) : -EBADF;
        errno = -added;
        EXPECT(added == 0, "sbx_local_add_mode read and write");
        fd = open("/sandbox-local/rw.txt", O_WRONLY | O_TRUNC);
        EXPECT(fd >= 0, "a writable local file opens for writing");
        if (fd >= 0) {
            EXPECT(write(fd, "new", 3) == 3, "and writes");
            close(fd);
        }
        fd = open("/sandbox-local/rw.txt", O_RDONLY);
        EXPECT(fd >= 0, "and opens again for reading");
        if (fd >= 0) {
            read_word(fd, word, sizeof(word));
            EXPECT(strcmp(word, "new") == 0, "O_TRUNC emptied it and the write is there");
            close(fd);
        }
        fd = open(local_path, O_RDONLY);
        EXPECT(sbx_local_add_mode("/sandbox-local/rw.txt", fd, SBX_WRITE) == -EINVAL, "sbx_local_add_mode: write alone is no mode");
        fd = open(local_path, O_RDONLY);
        EXPECT(sbx_local_add_mode("/sandbox-local/rw.txt", fd, SBX_READ) == 0, "a local file replaced read only");
        errno = 0;
        EXPECT(refused(open("/sandbox-local/rw.txt", O_WRONLY)), "takes the new mode: no longer writable");

        errno = 0;
        EXPECT(refused(socket(AF_INET, SOCK_STREAM, 0)), "passthrough: socket(AF_INET) refused");
        errno = 0;
        EXPECT(a_exec() == EACCES, "passthrough: execve refused");
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/*
 * SBX_LIST, asked of the broker directly, as the handler asks it for a
 * folder the kernel would not list for the confined process (which this
 * test, one user throughout, cannot make happen).
 */
static long ask_list(int broker_fd, int dir, char *out, size_t out_len) {
    int answer[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, answer) != 0) return -errno;
    struct {
        uint16_t version, op;
        int32_t flags;
        uint32_t mode, path_len, path2_len;
        int32_t tid;
        uint8_t dirfd_sent, dirfd2_sent, reserved[6];
    } request = {.version = 1, .op = 11 /* SBX_LIST */, .mode = (uint32_t) out_len, .path_len = 1,
                 .tid = (int32_t) syscall(__NR_gettid), .dirfd_sent = 1};
    struct iovec parts[2] = {{&request, sizeof(request)}, {(void *) ".", 1}};
    int fds[2] = {answer[1], dir};
    union {
        char buffer[CMSG_SPACE(sizeof(fds))];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message = {.msg_iov = parts, .msg_iovlen = 2, .msg_control = control.buffer,
                             .msg_controllen = sizeof(control.buffer)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(fds));
    memcpy(CMSG_DATA(header), fds, sizeof(fds));
    long sent = sendmsg(broker_fd, &message, 0);
    close(answer[1]);
    if (sent < 0) { close(answer[0]); return -errno; }
    struct { int64_t result; uint32_t data_len, reserved; } reply;
    struct iovec back[2] = {{&reply, sizeof(reply)}, {out, out_len}};
    struct msghdr answer_message = {.msg_iov = back, .msg_iovlen = 2};
    long got = recvmsg(answer[0], &answer_message, 0);
    close(answer[0]);
    if (got < (long) sizeof(reply)) return -EIO;
    return (long) reply.result;
}

static int names(const char *records, long n, const char *name) {
    for (long at = 0; at < n;) {
        const struct { uint64_t ino; int64_t off; unsigned short reclen; unsigned char type; char name[]; } *d =
            (const void *) (records + at);
        if (strcmp(d->name, name) == 0) return 1;
        if (d->reclen == 0) break;
        at += d->reclen;
    }
    return 0;
}

static int list_check(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, save, SBX_READ);
    if (sbx_broker_prepare(pair[0]) != 0 || sbx_broker_start(policy, pair[0]) != 0) return 1;
    char records[4096];
    int dir = open(save, O_RDONLY | O_DIRECTORY);
    long n = dir >= 0 ? ask_list(pair[1], dir, records, sizeof(records)) : -EBADF;
    EXPECT(n > 0 && names(records, n, "revoked.txt"), "SBX_LIST: the broker lists a folder under a read rule");
    long more = dir >= 0 ? ask_list(pair[1], dir, records, sizeof(records)) : -EBADF;
    EXPECT(more == 0, "SBX_LIST: from the same position, so the next read is the end");
    if (dir >= 0) {
        lseek(dir, 0, SEEK_SET);
        n = ask_list(pair[1], dir, records, sizeof(records));
        EXPECT(n > 0 && names(records, n, "revoked.txt"), "SBX_LIST: and again after a rewind");
        close(dir);
    }
    dir = open(secret, O_RDONLY | O_DIRECTORY);
    n = dir >= 0 ? ask_list(pair[1], dir, records, sizeof(records)) : -EBADF;
    errno = n < 0 ? (int) -n : 0;
    EXPECT(n == -EACCES, "SBX_LIST: a folder outside the rules is refused");
    if (dir >= 0) close(dir);
    close(pair[1]);
    return failures ? 1 : 0;
}

/* ---- Fewer round trips (Droidtop/tracker#791): sbx_list_stat and the broker's parent cache. ---- */

static int perf_count(int fd, size_t buffer_size, int *with_stat, int *link_as_link, long *size_of_big, int *denied_no_stat) {
    static char records[32768];
    int entries = 0;
    long got;
    while ((got = sbx_list_stat(fd, records, buffer_size)) > 0) {
        for (long at = 0; at < got;) {
            const struct sbx_list_stat_entry *e = (const void *) (records + at);
            entries++;
            if (e->has_stat) (*with_stat)++;
            if (strcmp(e->name, "link") == 0 && e->has_stat && S_ISLNK(e->mode)) *link_as_link = 1;
            if (strcmp(e->name, "big") == 0 && e->has_stat) *size_of_big = (long) e->size;
            if (strcmp(e->name, "hidden") == 0 && !e->has_stat) *denied_no_stat = 1;
            at += e->record_len;
        }
    }
    return got < 0 ? (int) got : entries;
}

struct perf_broker {
    struct sbx_policy *policy;
    int fd;
};

static void *perf_serve(void *argument) {
    struct perf_broker *b = argument;
    sbx_broker_serve(b->policy, b->fd);
    return NULL;
}

static int perf_check(void) {
    char tree[400], hidden[500], outside[400], swap[400], secret_dir[400], secret_file[500], path[600];
    snprintf(tree, sizeof(tree), "%s/perf", root);
    snprintf(hidden, sizeof(hidden), "%s/perf/hidden", root);
    snprintf(outside, sizeof(outside), "%s/perf-outside", root);
    snprintf(swap, sizeof(swap), "%s/perf/swap", root);
    snprintf(secret_dir, sizeof(secret_dir), "%s/perf-secret", root);
    snprintf(secret_file, sizeof(secret_file), "%s/perf-secret/f", root);
    mkdir(tree, 0755);
    mkdir(hidden, 0755);
    mkdir(outside, 0755);
    mkdir(swap, 0755);
    mkdir(secret_dir, 0755);
    write_file(secret_file, "secret");
    for (int i = 0; i < 300; i++) {
        snprintf(path, sizeof(path), "%s/file-with-a-longish-name-%03d", tree, i);
        write_file(path, "x");
    }
    snprintf(path, sizeof(path), "%s/big", tree);
    write_file(path, "0123456789");
    snprintf(path, sizeof(path), "%s/link", tree);
    symlink(secret_file, path);
    snprintf(path, sizeof(path), "%s/f", swap);
    write_file(path, "in the swap folder");
    int outside_fd = open(outside, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, tree, SBX_READ);
    sbx_policy_add(policy, hidden, SBX_DENY);
    int pair[2], go[2], ready[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0 || pipe(go) != 0 || pipe(ready) != 0 ||
        sbx_broker_prepare(pair[0]) != 0) {
        return 1;
    }
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(60);
        close(pair[0]);
        close(go[1]);
        close(ready[0]);
        struct sbx_lockdown_options options = {.flags = 0};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "list_stat: lockdown");
        if (locked == 0) {
            int fd = open(tree, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            int with_stat = 0, link_as_link = 0, denied_no_stat = 0;
            long big = -1;
            int entries = fd >= 0 ? perf_count(fd, 32768, &with_stat, &link_as_link, &big, &denied_no_stat) : -1;
            /* 300 files, big, link, hidden and swap: 304 entries; all but hidden with their metadata. */
            EXPECT(entries == 304 && with_stat == 303, "list_stat: a folder's entries with their metadata, in few requests");
            EXPECT(big == 10, "list_stat: an entry's size");
            EXPECT(link_as_link, "list_stat: a link is reported as itself, never followed");
            EXPECT(denied_no_stat, "list_stat: an entry under a deny rule comes without its metadata");
            if (fd >= 0) close(fd);
            fd = open(tree, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            with_stat = 0;
            int paged = fd >= 0 ? perf_count(fd, 512, &with_stat, &link_as_link, &big, &denied_no_stat) : -1;
            EXPECT(paged == 304 && with_stat == 303, "list_stat: a small buffer pages through the folder, no entry lost or repeated");
            if (fd >= 0) close(fd);
            static char records[1024];
            EXPECT(outside_fd >= 0 && sbx_list_stat(outside_fd, records, sizeof(records)) == -EACCES,
                   "list_stat: a folder outside the rules is refused, even through a descriptor held from before");
            /* The parent cache: the swap folder is resolved and kept; then replaced, from outside, by a link to a secret. */
            char inside[600], stale[600];
            snprintf(inside, sizeof(inside), "%s/f", swap);
            snprintf(stale, sizeof(stale), "%s/f", swap);
            struct stat st;
            EXPECT(stat(inside, &st) == 0, "parent cache: a file in a folder, resolved and kept");
            ssize_t told = write(ready[1], "r", 1);
            (void) told;
            char byte;
            /* The parent swaps the folder, then writes one byte. */
            EXPECT(read(go[0], &byte, 1) == 1, "parent cache: the folder swapped for a link, from outside the broker");
            int opened = open(stale, O_RDONLY | O_CLOEXEC);
            EXPECT(opened < 0 && errno == EACCES,
                   "parent cache: within its lifetime, a stale entry refuses; the secret behind the link is never opened");
            if (opened >= 0) close(opened);
        }
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    close(go[0]);
    close(ready[1]);
    /* The broker runs on a thread, so this process can swap the folder while the child is locked down. */
    pthread_t broker_thread;
    struct perf_broker args = {policy, pair[0]};
    pthread_create(&broker_thread, NULL, perf_serve, &args);
    char byte;
    if (read(ready[0], &byte, 1) != 1) printf("info parent cache: the child never got to the swap\n");
    close(ready[0]);
    char moved[500];
    snprintf(moved, sizeof(moved), "%s-moved", swap);
    rename(swap, moved);
    symlink(secret_dir, swap);
    ssize_t w = write(go[1], "s", 1);
    (void) w;
    close(go[1]);
    int status = 0;
    waitpid(child, &status, 0);
    pthread_join(broker_thread, NULL);
    if (outside_fd >= 0) close(outside_fd);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* ---- Folders held by path (Droidtop/tracker#741): an isolated process is refused folder descriptors. ---- */

static int count_entries(DIR *dir, int *saw_sub) {
    int n = 0;
    struct dirent *e;
    while ((e = readdir(dir))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        if (strcmp(e->d_name, "sub") == 0 && saw_sub) *saw_sub = 1;
        n++;
    }
    return n;
}

/*
 * With sbx_policy_set_folders_by_path the broker answers a folder's open
 * with its path and no descriptor, as Android's SELinux leaves an isolated
 * process: every folder call is then the handler's, by that path. Run
 * brokered and in passthrough (the folder claimed).
 */
static int folders_check(int pass) {
    const char *mode = pass ? "folders by path (passthrough)" : "folders by path";
    char tree[400], sub[500], hidden[500], path[600], what[200];
    snprintf(tree, sizeof(tree), "%s/held-%d", root, pass);
    snprintf(sub, sizeof(sub), "%s/sub", tree);
    snprintf(hidden, sizeof(hidden), "%s/hidden", tree);
    mkdir(tree, 0755);
    mkdir(sub, 0755);
    mkdir(hidden, 0755);
    for (int i = 0; i < 300; i++) {
        snprintf(path, sizeof(path), "%s/file-with-a-longish-name-%03d", tree, i);
        write_file(path, "x");
    }
    snprintf(path, sizeof(path), "%s/first", tree);
    write_file(path, "first file");
    struct stat tree_st;
    if (stat(tree, &tree_st) != 0) return 1;

    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, tree, SBX_READ | SBX_WRITE);
    sbx_policy_add(policy, hidden, SBX_DENY);
    sbx_policy_set_folders_by_path(policy, 1);
    if (sbx_broker_prepare(pair[0]) != 0 || sbx_broker_start(policy, pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(60);
        close(pair[0]);
        const char *claims[] = {tree};
        struct sbx_lockdown_options options = {.flags = pass ? SBX_LOCK_PASSTHROUGH : 0, .claims = claims,
                                               .claim_count = pass ? 1 : 0};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        snprintf(what, sizeof(what), "%s: lockdown", mode);
        EXPECT(locked == 0, what);
        if (locked != 0) _exit(1);

        int fd = open(tree, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        snprintf(what, sizeof(what), "%s: a folder's open answers a descriptor, not EIO", mode);
        EXPECT(fd >= 0, what);
        if (fd < 0) _exit(1);
        struct stat st;
        snprintf(what, sizeof(what), "%s: fstat names the folder itself (its inode, a directory)", mode);
        EXPECT(fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_ino == tree_st.st_ino && st.st_dev == tree_st.st_dev, what);
        char link[64], target[600];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(link, target, sizeof(target) - 1);
        if (n >= 0) target[n] = '\0';
        snprintf(what, sizeof(what), "%s: readlink of /proc/self/fd/<it> is the folder's path (realpath reads it)", mode);
        EXPECT(n > 0 && strcmp(target, tree) == 0, what);

        /* readdir, over several requests (301 entries and sub), then again after a rewind. */
        int dup_fd = dup(fd);
        DIR *dir = fdopendir(fd);
        int saw_sub = 0;
        int entries = dir ? count_entries(dir, &saw_sub) : -1;
        snprintf(what, sizeof(what), "%s: readdir lists every entry, over several requests", mode);
        EXPECT(entries == 303 && saw_sub, what);
        if (dir) rewinddir(dir);
        entries = dir ? count_entries(dir, NULL) : -1;
        snprintf(what, sizeof(what), "%s: and again after rewinddir", mode);
        EXPECT(entries == 303, what);

        /* Calls relative to it, and fchdir. */
        int file = dir ? openat(dirfd(dir), "first", O_RDONLY | O_CLOEXEC) : -1;
        char word[32] = {0};
        snprintf(what, sizeof(what), "%s: openat relative to it opens the file in the folder", mode);
        EXPECT(file >= 0 && read(file, word, sizeof(word) - 1) == 10 && strcmp(word, "first file") == 0, what);
        if (file >= 0) close(file);
        snprintf(what, sizeof(what), "%s: fstatat relative to it", mode);
        EXPECT(dir && fstatat(dirfd(dir), "sub", &st, 0) == 0 && S_ISDIR(st.st_mode), what);
        snprintf(what, sizeof(what), "%s: mkdirat relative to it makes the folder where it belongs", mode);
        EXPECT(dir && mkdirat(dirfd(dir), "made", 0700) == 0, what);
        snprintf(what, sizeof(what), "%s: a folder under a deny rule stays refused, relative to it", mode);
        EXPECT(dir && openat(dirfd(dir), "hidden", O_RDONLY | O_DIRECTORY | O_CLOEXEC) < 0 && errno == EACCES, what);
        static char records[1024];
        snprintf(what, sizeof(what), "%s: sbx_list_stat answers EOPNOTSUPP on it", mode);
        EXPECT(dir && sbx_list_stat(dirfd(dir), records, sizeof(records)) == -EOPNOTSUPP, what);
        snprintf(what, sizeof(what), "%s: it cannot be duplicated out of the range", mode);
        EXPECT(dir && dup3(dirfd(dir), 50, O_CLOEXEC) < 0 && errno == EBADF, what);
        int held_number = dir ? dirfd(dir) : -1;
        if (dir) closedir(dir);
        snprintf(what, sizeof(what), "%s: closed, its descriptor is gone", mode);
        EXPECT(fcntl(held_number, F_GETFD) < 0 && errno == EBADF, what);
        snprintf(what, sizeof(what), "%s: a duplicate is a folder of its own, still listed after the original closed", mode);
        DIR *again = dup_fd >= 0 ? fdopendir(dup_fd) : NULL;
        EXPECT(again && count_entries(again, NULL) == 304, what);  /* with "made" */
        if (again) {
            snprintf(what, sizeof(what), "%s: fchdir to it; a relative open and getcwd go by its path", mode);
            char cwd[600];
            int ok = fchdir(dirfd(again)) == 0;
            int rel = ok ? open("first", O_RDONLY | O_CLOEXEC) : -1;
            EXPECT(ok && rel >= 0 && getcwd(cwd, sizeof(cwd)) && strcmp(cwd, tree) == 0, what);
            if (rel >= 0) close(rel);
            closedir(again);
        }
        snprintf(what, sizeof(what), "%s: chdir by name to a folder held by path, then up and back", mode);
        char cwd[600];
        EXPECT(chdir(sub) == 0 && getcwd(cwd, sizeof(cwd)) && strcmp(cwd, sub) == 0 && chdir("..") == 0 &&
               getcwd(cwd, sizeof(cwd)) && strcmp(cwd, tree) == 0, what);
        snprintf(what, sizeof(what), "%s: a folder under a deny rule is refused", mode);
        EXPECT(open(hidden, O_RDONLY | O_DIRECTORY | O_CLOEXEC) < 0 && errno == EACCES, what);

        /* The range is finite: past it an open fails EMFILE, and closing frees it. */
        int many[80], opened = 0, last_error = 0;
        for (int i = 0; i < 80; i++) {
            many[i] = open(sub, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (many[i] >= 0) opened++;
            else last_error = errno;
        }
        snprintf(what, sizeof(what), "%s: at most 64 at once (one is the current directory), then EMFILE", mode);
        EXPECT(opened == 63 && last_error == EMFILE, what);
        for (int i = 0; i < 80; i++) {
            if (many[i] >= 0) close(many[i]);
        }
        int one = open(sub, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        snprintf(what, sizeof(what), "%s: closed, the range is free again", mode);
        EXPECT(one >= 0, what);
        if (one >= 0) close(one);
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    struct stat made;
    snprintf(path, sizeof(path), "%s/made", tree);
    snprintf(what, sizeof(what), "%s: the folder made relative to it is there", mode);
    EXPECT(stat(path, &made) == 0 && S_ISDIR(made.st_mode), what);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
