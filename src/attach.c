/*
 * The confined side of sbx_broker_listen: a process connects to the
 * host's broker by path, proves itself with the launch's token (and the
 * kernel's word for its UID), and locks down on that connection. This is
 * how every process of a tree the host starts with libsbx_child.so on
 * LD_PRELOAD confines itself before its main runs (docs/design.md, "Wine
 * and proot under the broker").
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "sbx.h"
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

extern char **environ;

int sbx_attach(const char *socket_path, const char *token, const struct sbx_lockdown_options *options) {
    if (!socket_path || socket_path[0] != '/' || !token || !token[0]) return -EINVAL;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t length = strlen(socket_path);
    if (length >= sizeof(address.sun_path)) return -ENAMETOOLONG;
    memcpy(address.sun_path, socket_path, length + 1);
    /* Not close-on-exec: the images this process runs keep the connection (SBX_BROKER_FD). */
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) return -errno;
    int on = 1;
    int error = 0;
    /* Credentials on every message this connection carries, whichever process sends it. */
    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) != 0) error = -errno;
    else if (connect(fd, (struct sockaddr *) &address, sizeof(address)) != 0) error = -errno;
    else if (send(fd, token, strlen(token), MSG_NOSIGNAL) < 0) error = -errno;
    if (error == 0) {
        char ok = 0;
        ssize_t n;
        do n = recv(fd, &ok, 1, 0);
        while (n < 0 && errno == EINTR);
        if (n != 1 || ok != 1) error = n < 0 ? -errno : -EACCES;
    }
    if (error == 0) {
        char number[16];
        snprintf(number, sizeof(number), "%d", fd);
        if (setenv("SBX_BROKER_FD", number, 1) != 0) error = -ENOMEM;
    }
    if (error == 0) error = sbx_lockdown(fd, options);
    if (error != 0) {
        close(fd);
        unsetenv("SBX_BROKER_FD");
    }
    return error;
}

/* Overwrites a variable's value where it lives (so /proc/<pid>/environ no longer shows it), then removes it. */
static void scrub(const char *name) {
    size_t n = strlen(name);
    for (char **entry = environ; entry && *entry; entry++) {
        if (strncmp(*entry, name, n) == 0 && (*entry)[n] == '=') {
            char *value = *entry + n + 1;
            memset(value, 0, strlen(value));
        }
    }
    unsetenv(name);
}

/* A descriptor or flags number from the environment, or -1. */
static long number_from(const char *name) {
    const char *text = getenv(name);
    if (!text || !text[0]) return -1;
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 0);
    if (errno != 0 || *end != '\0' || value > 0x7fffffffUL) return -1;
    return (long) value;
}

/*
 * An image sbx-exec started (SBX_LOCK_EXEC): the filter is already in
 * place and kept by the exec, so the process takes over the connection
 * and descriptors it was handed instead of attaching. Fails closed: a
 * missing or bad name, or no filter behind them, is an error, and the
 * child library ends the process.
 */
static int adopt_from_environment(void) {
    long broker_fd = number_from("SBX_BROKER_FD"), cwd_fd = number_from("SBX_CWD_FD");
    long helper_fd = number_from("SBX_EXEC_HELPER_FD"), flags = number_from("SBX_FLAGS");
    const char *library = getenv("SBX_CHILD_LIBRARY");
    if (broker_fd < 0 || cwd_fd < 0 || helper_fd < 0 || flags < 0 || !library) return -EINVAL;
    char copy[4096];
    if (snprintf(copy, sizeof(copy), "%s", library) >= (int) sizeof(copy)) return -ENAMETOOLONG;
    int result = sbx_adopt((unsigned) flags, (int) broker_fd, (int) cwd_fd, (int) helper_fd, copy);
    if (result == 0) {
        /* The program's own environment again; SBX_BROKER_FD stays, as sbx_attach leaves it. */
        unsetenv("SBX_ADOPT");
        unsetenv("SBX_CWD_FD");
        unsetenv("SBX_FLAGS");
        unsetenv("SBX_EXEC_HELPER_FD");
        unsetenv("SBX_CHILD_LIBRARY");
    }
    return result;
}

int sbx_attach_from_environment(void) {
    const char *adopt = getenv("SBX_ADOPT");
    if (adopt && strcmp(adopt, "1") == 0) return adopt_from_environment();
    const char *broker = getenv("SBX_BROKER");
    if (!broker) return 1;
    const char *token = getenv("SBX_TOKEN");
    const char *flags_text = getenv("SBX_FLAGS");
    if (!token) return -EINVAL;
    unsigned flags = 0;
    if (flags_text && flags_text[0]) {
        char *end = NULL;
        errno = 0;
        unsigned long value = strtoul(flags_text, &end, 0);
        if (errno != 0 || *end != '\0' || value > 0xffffffffUL) return -EINVAL;
        flags = (unsigned) value;
    }
    /* Device paths the process opens itself before lockdown (a GPU driver's node). */
    const char *own[SBX_OWN_OPENS_MAX];
    unsigned own_count = 0;
    char *copy = NULL;
    const char *own_text = getenv("SBX_OWN_OPENS");
    if (own_text && own_text[0]) {
        copy = strdup(own_text);
        if (!copy) return -ENOMEM;
        for (char *save = NULL, *path = strtok_r(copy, ":", &save); path; path = strtok_r(NULL, ":", &save)) {
            if (own_count == SBX_OWN_OPENS_MAX) {
                free(copy);
                return -E2BIG;
            }
            own[own_count++] = path;
        }
    }
    struct sbx_lockdown_options options;
    memset(&options, 0, sizeof(options));
    options.flags = flags;
    options.own_opens = own_count ? own : NULL;
    options.own_open_count = own_count;
    /* SBX_LOCK_EXEC (in SBX_LOCK_CONTAIN): the host's sbx-exec and this library, by absolute path. */
    static char helper[4096], library[4096];
    const char *helper_text = getenv("SBX_EXEC_HELPER"), *library_text = getenv("SBX_CHILD_LIBRARY");
    if (helper_text) {
        snprintf(helper, sizeof(helper), "%s", helper_text);
        options.exec_helper = helper;
    }
    if (library_text) {
        snprintf(library, sizeof(library), "%s", library_text);
        options.child_library = library;
    }
    char path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
    snprintf(path, sizeof(path), "%s", broker);
    char secret[128];
    snprintf(secret, sizeof(secret), "%s", token);
    int result = sbx_attach(path, secret, &options);
    memset(secret, 0, sizeof(secret));
    /* own_opens' paths are copied by sbx_lockdown; the list itself is not kept. */
    free(copy);
    if (result == 0) {
        scrub("SBX_TOKEN");
        unsetenv("SBX_BROKER");
        /* The handler keeps the helper open and passes both on to each image it execs. */
        unsetenv("SBX_EXEC_HELPER");
        unsetenv("SBX_CHILD_LIBRARY");
    }
    return result;
}
