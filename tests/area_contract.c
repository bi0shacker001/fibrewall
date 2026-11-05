/*
 * sbx_test, area "contract": the confinement contract and bounded zones.
 * Included by tests/sbx_test.c, one translation unit with the harness (tests/sbx_test.h);
 * SBX_TEST_AREA=contract runs this area alone (#767).
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */

/* ---- Inet: inet sockets and nothing else that reaches out. ---- */

/* ---- The confinement contract: sbx_negotiate's report, and sbx_lockdown_checked's gate. ---- */

static int contract_check(void) {
    struct sbx_report r;
    struct sbx_requirements req;

    struct sbx_lockdown_options base = {.flags = 0};
    memset(&r, 0, sizeof(r));
    r.size = sizeof(r);
    EXPECT(sbx_negotiate(NULL, &base, NULL, &r) == 0, "contract: a plain lockdown negotiates");
    uint64_t want = SBX_G_FS_MEDIATED | SBX_G_NET_NONE | SBX_G_SIGNALS_SELF | SBX_G_EXEC_NONE | SBX_G_NOT_LEARNING |
                    SBX_G_NO_DEVICES;
    EXPECT((r.effective & want) == want, "contract: a plain lockdown's guarantees are effective");
    EXPECT(r.blocking & SBX_G_IPC_NONE, "contract: IPC-none is ruled out on this backend");
    EXPECT((r.residual & (SBX_R_HOST_UID | SBX_R_KERNEL_SURFACE)) == (SBX_R_HOST_UID | SBX_R_KERNEL_SURFACE),
           "contract: the host uid and kernel surface are residual");
    EXPECT(r.backend[0] != '\0' && r.backend_version != 0, "contract: the backend is named and versioned");

    memset(&req, 0, sizeof(req));
    req.size = sizeof(req);
    req.required = SBX_G_NET_NONE;
    EXPECT(sbx_negotiate(NULL, &base, &req, &r) == 0, "contract: requiring no-network is met by a plain lockdown");
    req.required = SBX_G_IPC_NONE;
    EXPECT(sbx_negotiate(NULL, &base, &req, &r) == -EPERM && r.reason[0], "contract: requiring no-IPC fails, with a reason");
    req.required = 0;
    req.forbidden = SBX_R_HOST_UID;
    EXPECT(sbx_negotiate(NULL, &base, &req, &r) == -EPERM, "contract: forbidding the host uid fails a same-uid lockdown");

    struct sbx_lockdown_options inet = {.flags = SBX_LOCK_INET};
    memset(&req, 0, sizeof(req));
    req.size = sizeof(req);
    req.required = SBX_G_NET_NONE;
    EXPECT(sbx_negotiate(NULL, &inet, &req, &r) == -EPERM, "contract: INET cannot satisfy no-network");
    EXPECT((r.blocking & SBX_G_NET_NONE) && (r.residual & SBX_R_NETWORK_ANY), "contract: INET blocks no-network, leaves network residual");

    struct sbx_lockdown_options contain = {.flags = SBX_LOCK_CONTAIN, .exec_helper = "h", .child_library = "/l"};
    EXPECT(sbx_negotiate(NULL, &contain, NULL, &r) == 0, "contract: the containment preset negotiates");
    EXPECT((r.effective & SBX_G_EXEC_CONFINED) && !(r.effective & SBX_G_SIGNALS_SELF), "contract: CONTAIN confines exec, opens signals");
    EXPECT((r.residual & SBX_R_UID_SIGNALS) && (r.residual & SBX_R_UID_SOCKETS), "contract: CONTAIN leaves uid signals and sockets residual");

    struct sbx_report r2;
    memset(&r2, 0, sizeof(r2));
    r2.size = sizeof(r2);
    sbx_negotiate(NULL, &base, NULL, &r);
    sbx_negotiate(NULL, &base, NULL, &r2);
    EXPECT(memcmp(r.policy_digest, r2.policy_digest, 32) == 0, "contract: the same policy digests the same");
    sbx_negotiate(NULL, &inet, NULL, &r2);
    EXPECT(memcmp(r.policy_digest, r2.policy_digest, 32) != 0, "contract: different flags digest differently");

    memset(&r, 0, sizeof(r));
    EXPECT(sbx_negotiate(NULL, &base, NULL, &r) == -EINVAL, "contract: a report without its size is refused");

    /* The gate installs or refuses, and nothing in between. */
    fflush(stdout);
    pid_t met = fork();
    if (met == 0) {
        struct sbx_lockdown_options o = {.flags = SBX_LOCK_UNBROKERED};
        struct sbx_requirements want_none = {.size = sizeof(want_none), .required = SBX_G_NET_NONE};
        struct sbx_report rep = {.size = sizeof(rep)};
        if (sbx_lockdown_checked(-1, &o, &want_none, &rep) != 0) _exit(1);
        _exit(socket(AF_INET, SOCK_STREAM, 0) < 0 && errno == EACCES ? 0 : 2);  /* locked: no sockets */
    }
    int status = 0;
    waitpid(met, &status, 0);
    EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "contract: a met requirement locks down, and the filter holds");

    fflush(stdout);
    pid_t unmet = fork();
    if (unmet == 0) {
        struct sbx_lockdown_options o = {.flags = SBX_LOCK_UNBROKERED};
        struct sbx_requirements impossible = {.size = sizeof(impossible), .required = SBX_G_IPC_NONE};
        struct sbx_report rep = {.size = sizeof(rep)};
        if (sbx_lockdown_checked(-1, &o, &impossible, &rep) != -EPERM) _exit(1);
        int s = socket(AF_INET, SOCK_STREAM, 0);  /* not locked: a socket is still possible */
        if (s >= 0) close(s);
        _exit(s >= 0 ? 0 : 2);
    }
    waitpid(unmet, &status, 0);
    EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "contract: an unmet requirement installs nothing");

    return failures ? 1 : 0;
}

/*
 * A-02: ioctl(fd, TIOCSTI) and ioctl(fd, TIOCLINUX) push bytes into the
 * input queue of a terminal the process inherited, so a confined process
 * could plant a command the shell runs after it exits. The filter refuses
 * both on any descriptor; a harmless ioctl still reaches the kernel.
 */
#ifndef TIOCLINUX
#define TIOCLINUX 0x541c
#endif
/* ---- Bounded zones (sbx_zones.h; docs/zones.md, Droidtop/tracker#651). ---- */

static int zt_asks, zt_remembered;
static unsigned short zt_port_yes;
static char zt_stored_detail[400];

static enum sbx_zone zt_recall(void *context, const char *game, const char *entry, const char *detail) {
    (void) context;
    (void) game;
    if (zt_remembered && strcmp(entry, "files.own.write") == 0 && strcmp(detail, zt_stored_detail) == 0) return SBX_ZONE_ALLOW;
    return SBX_ZONE_PROMPT;
}

static enum sbx_zone zt_ask(void *context, const struct sbx_zone_question *q, int *remember) {
    (void) context;
    __atomic_add_fetch(&zt_asks, 1, __ATOMIC_ACQ_REL);
    if (strcmp(q->entry, "files.own.write") == 0) {
        usleep(600 * 1000);  /* a person taking their time: only the asking thread may wait */
        *remember = 1;
        return SBX_ZONE_ALLOW;
    }
    if (strcmp(q->entry, "files.nearby.read") == 0) return SBX_ZONE_ALLOW;
    if (strcmp(q->entry, "net.local") == 0) {
        char yes[16];
        snprintf(yes, sizeof(yes), ":%u", (unsigned) zt_port_yes);
        size_t n = strlen(q->detail), m = strlen(yes);
        return n >= m && strcmp(q->detail + n - m, yes) == 0 ? SBX_ZONE_ALLOW : SBX_ZONE_DENY;
    }
    return SBX_ZONE_DENY;
}

static void zt_remember(void *context, const char *game, const char *entry, const char *detail, enum sbx_zone answer) {
    (void) context;
    (void) game;
    if (strcmp(entry, "files.own.write") == 0 && answer == SBX_ZONE_ALLOW) {
        snprintf(zt_stored_detail, sizeof(zt_stored_detail), "%s", detail);
        __atomic_store_n(&zt_remembered, 1, __ATOMIC_RELEASE);
    }
}

struct zt_reader {
    char path[600];
    long elapsed_ms;
    int ok;
};

static long zt_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void *zt_read_thread(void *argument) {
    struct zt_reader *r = argument;
    usleep(150 * 1000);  /* while the other thread's write waits on the person */
    long start = zt_now_ms();
    struct stat st;
    r->ok = stat(r->path, &st) == 0;
    r->elapsed_ms = zt_now_ms() - start;
    return NULL;
}

static int zones_check(void) {
    /* The catalogue and the shipped profiles. */
    EXPECT(sbx_zone_catalogue_version() == 1 && sbx_zone_entry(0) && strcmp(sbx_zone_entry(0)->id, "files.own.write") == 0 &&
               sbx_zone_entry(10) && !sbx_zone_entry(11),
           "zones: the catalogue's eleven entries");
    const struct sbx_zone_profile *careful = sbx_zone_shipped("careful");
    EXPECT(careful && sbx_zone_of(careful, "files.own.write") == SBX_ZONE_ALLOW &&
               sbx_zone_of(careful, "net.internet") == SBX_ZONE_DENY && sbx_zone_of(careful, "programs.own") == SBX_ZONE_PROMPT,
           "zones: careful, the default profile");
    int internet_never_allowed = 1;
    const char *names[] = {"locked", "careful", "balanced", "relaxed", "open"};
    for (int i = 0; i < 5; i++) {
        const struct sbx_zone_profile *p = sbx_zone_shipped(names[i]);
        if (!p || sbx_zone_of(p, "net.internet") == SBX_ZONE_ALLOW || sbx_zone_of(p, "files.picked.read") == SBX_ZONE_ALLOW) {
            internet_never_allowed = 0;
        }
    }
    EXPECT(internet_never_allowed && !sbx_zone_shipped("reckless"),
           "zones: no shipped profile allows the internet or a picked folder without asking");

    /* The person's own profiles. */
    struct sbx_zone_profile *own = NULL;
    char error[160];
    int parsed = sbx_zone_profile_parse("sbx-zones 1\nname: Mine\nbased-on: balanced\n# a comment\nnet.internet = allow\n",
                                        &own, error, sizeof(error));
    EXPECT(parsed == 0 && own && sbx_zone_of(own, "net.internet") == SBX_ZONE_ALLOW &&
               sbx_zone_of(own, "net.local") == SBX_ZONE_PROMPT && strcmp(sbx_zone_profile_name(own), "Mine") == 0,
           "zones: a person's own profile, the rest from based-on");
    sbx_zone_profile_free(own);
    struct sbx_zone_profile *bad = NULL;
    EXPECT(sbx_zone_profile_parse("sbx-zones 1\nnet.everything = allow\n", &bad, error, sizeof(error)) == -EINVAL && !bad &&
               strstr(error, "no entry"),
           "zones: an id the catalogue lacks is an error");
    EXPECT(sbx_zone_profile_parse("sbx-zones 1\nprograms.outside = allow\n", &bad, error, sizeof(error)) == -EINVAL &&
               strstr(error, "every profile"),
           "zones: the never layer cannot be granted");
    EXPECT(sbx_zone_profile_parse("sbx-zones 2\n", &bad, error, sizeof(error)) == -EINVAL && strstr(error, "newer"),
           "zones: a profile from a newer library is refused");
    EXPECT(sbx_zone_profile_parse("net.local = allow\n", &bad, error, sizeof(error)) == -EINVAL,
           "zones: the version line is required");
    EXPECT(sbx_zone_profile_parse("sbx-zones 1\nnet.local = maybe\n", &bad, error, sizeof(error)) == -EINVAL,
           "zones: a zone is allow, prompt or deny");

    /* Applied: a program whose own writes and local network are asked, nearby folders asked, the internet denied. */
    struct sbx_zone_profile *profile = NULL;
    parsed = sbx_zone_profile_parse("sbx-zones 1\nbased-on: careful\nfiles.own.write = prompt\nnet.local = prompt\n", &profile,
                                    error, sizeof(error));
    EXPECT(parsed == 0, "zones: the test's profile");
    if (parsed != 0) return 1;
    char folder[400], library[400], other[400], nearby_file[500], inside[500];
    snprintf(library, sizeof(library), "%s/zlib", root);
    snprintf(folder, sizeof(folder), "%s/zlib/game", root);
    snprintf(other, sizeof(other), "%s/zlib/other", root);
    snprintf(nearby_file, sizeof(nearby_file), "%s/zlib/other/readme", root);
    snprintf(inside, sizeof(inside), "%s/zlib/game/data", root);
    mkdir(library, 0755);
    mkdir(folder, 0755);
    mkdir(other, 0755);
    write_file(nearby_file, "nearby");
    write_file(inside, "data");
    unsigned short port_no = 0;
    int yes_server = nf_listen(SOCK_STREAM, &zt_port_yes), no_server = nf_listen(SOCK_STREAM, &port_no);
    struct sbx_policy *policy = sbx_policy_new();
    struct sbx_lockdown_options options = {.flags = 0};
    struct sbx_zone_game game = {.id = "test-game", .folder = folder, .library = library};
    struct sbx_zone_host host = {.recall = zt_recall, .ask = zt_ask, .remember = zt_remember};
    EXPECT(sbx_zone_apply(policy, &options, profile, &game, &host) == 0, "zones: apply");
    EXPECT((options.flags & SBX_LOCK_NET_BROKERED) && (options.flags & SBX_LOCK_NET_FILTER) &&
               !(options.flags & SBX_LOCK_EXEC) && !(options.flags & SBX_LOCK_WATCH),
           "zones: the flags the entries need, and no others");
    sbx_zone_profile_free(profile);
    sbx_policy_add(policy, "/", SBX_READ);  /* the test's own baseline: the system, to run at all */
    sbx_policy_add(policy, library, SBX_DENY);

    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0 || sbx_broker_prepare(pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(60);
        close(pair[0]);
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "zones: lockdown");
        if (locked == 0) {
            struct zt_reader reader;
            memset(&reader, 0, sizeof(reader));
            snprintf(reader.path, sizeof(reader.path), "%s", inside);
            pthread_t thread;
            pthread_create(&thread, NULL, zt_read_thread, &reader);
            char made[520];
            snprintf(made, sizeof(made), "%s/save1", folder);
            int fd = open(made, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
            EXPECT(fd >= 0, "zones: a write in its own folder, asked and allowed");
            if (fd >= 0) close(fd);
            pthread_join(thread, NULL);
            EXPECT(reader.ok && reader.elapsed_ms < 300,
                   "zones: while one thread waits on the person, the program's other calls go on (parked)");
            snprintf(made, sizeof(made), "%s/save2", folder);
            fd = open(made, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
            EXPECT(fd >= 0, "zones: a second write, answered from the remembered answer");
            if (fd >= 0) close(fd);
            fd = open(nearby_file, O_RDONLY | O_CLOEXEC);
            EXPECT(fd >= 0, "zones: a nearby folder, asked and allowed");
            if (fd >= 0) close(fd);
            EXPECT(nf_connect("127.0.0.1", zt_port_yes) == 0, "zones: a local address, asked and allowed");
            EXPECT(nf_connect("127.0.0.1", port_no) == EACCES, "zones: a local address, asked and refused");
            EXPECT(nf_connect("192.0.2.1", 80) == EACCES, "zones: the internet, denied without asking");
        }
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    sbx_broker_serve(policy, pair[0]);
    int status = 0;
    waitpid(child, &status, 0);
    int asks = __atomic_load_n(&zt_asks, __ATOMIC_ACQUIRE);
    int ok = asks == 4;
    printf("%s zones: the person was asked exactly four times (write once, nearby, two local addresses): %d\n",
           ok ? "ok  " : "FAIL", asks);
    if (yes_server >= 0) close(yes_server);
    if (no_server >= 0) close(no_server);
    return (WIFEXITED(status) ? WEXITSTATUS(status) : 1) | !ok;
}
