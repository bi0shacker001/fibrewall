/*
 * The Windows backend: confinement at spawn and an explicit broker.
 *
 * sbx_spawn starts a program suspended in an AppContainer with no
 * capabilities (less-privileged where the system has it), with child
 * processes refused, in a job object (one process, no breakaway, killed
 * when the job closes, UI and memory limits), inheriting only the handles
 * it is given. It grants the policy's SBX_STATIC folders to the container,
 * starts the broker on a thread, then lets the program run.
 *
 * The broker answers sbx_open requests on a one-instance message-mode pipe.
 * It opens under its own identity: the rules first, then the host's
 * decider; the parent folder by path, checking its final path is still
 * inside the rule (no junction or symlink leads out); the leaf relative to
 * that folder handle without following a reparse point; then it duplicates
 * the handle into the program with only the access asked for. A handle
 * carries only its own access, and an open relative to a folder handle is
 * checked against the program's token, so every file is a request.
 *
 * The reference is Chromium's Windows sandbox (sandbox/win), without its
 * interception of NtCreateFile: callers ask explicitly.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <userenv.h>

#include "sbx.h"
#include "windows_protocol.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Process-creation attributes some SDKs do not name. */
#ifndef PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
#define PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES 0x00020009
#endif
#ifndef PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY
#define PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY 0x0002000E
#endif
#ifndef PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY
#define PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY 0x0002000F
#endif
#ifndef PROCESS_CREATION_CHILD_PROCESS_RESTRICTED
#define PROCESS_CREATION_CHILD_PROCESS_RESTRICTED 0x01
#endif
#ifndef PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
#define PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT 0x01
#endif

/* NtCreateFile's dispositions and options. */
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_CREATE
#define FILE_CREATE 0x00000002
#endif
#ifndef FILE_OPEN_IF
#define FILE_OPEN_IF 0x00000003
#endif
#ifndef FILE_OVERWRITE
#define FILE_OVERWRITE 0x00000004
#endif
#ifndef FILE_OVERWRITE_IF
#define FILE_OVERWRITE_IF 0x00000005
#endif
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 0x00000001
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
#ifndef FILE_OPEN_REPARSE_POINT
#define FILE_OPEN_REPARSE_POINT 0x00200000
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#define STATUS_OBJECT_NAME_NOT_FOUND_ ((NTSTATUS) 0xC0000034L)
#define STATUS_OBJECT_PATH_NOT_FOUND_ ((NTSTATUS) 0xC000003AL)
#define STATUS_OBJECT_NAME_COLLISION_ ((NTSTATUS) 0xC0000035L)
#define STATUS_FILE_IS_A_DIRECTORY_ ((NTSTATUS) 0xC00000BAL)
#define STATUS_NOT_A_DIRECTORY_ ((NTSTATUS) 0xC0000103L)
#define STATUS_ACCESS_DENIED_ ((NTSTATUS) 0xC0000022L)

#define WRITING (SBX_OPEN_WRITE | SBX_OPEN_CREATE | SBX_OPEN_TRUNCATE | SBX_OPEN_EXCLUSIVE | SBX_OPEN_APPEND)
#define ALL_OPEN (SBX_OPEN_READ | WRITING | SBX_OPEN_DIRECTORY)
#define MODE_BITS (SBX_READ | SBX_WRITE | SBX_DECIDE | SBX_STATIC)
#define WPATH_MAX 32768

/* ---- Errors ---- */

/* The Windows error behind the last failure mapped here, for sbx_spawn_error(). */
static volatile DWORD last_error;

unsigned long sbx_spawn_error(void) { return last_error; }

static int errno_of(DWORD error) {
    last_error = error;
    switch (error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_DRIVE:
    case ERROR_BAD_NETPATH:
    case ERROR_BAD_NET_NAME:
        return ENOENT;
    case ERROR_ACCESS_DENIED:
    case ERROR_PRIVILEGE_NOT_HELD:
    case ERROR_CANT_ACCESS_FILE:
        return EACCES;
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
        return EEXIST;
    case ERROR_DIRECTORY:
        return ENOTDIR;
    case ERROR_FILENAME_EXCED_RANGE:
        return ENAMETOOLONG;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
        return ENOMEM;
    case ERROR_INVALID_NAME:
    case ERROR_INVALID_PARAMETER:
        return EINVAL;
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
        return EBUSY;
    case ERROR_NOT_SUPPORTED:
    case ERROR_CALL_NOT_IMPLEMENTED:
        return ENOSYS;
    case ERROR_INVALID_HANDLE:
        return EBADF;
    case ERROR_BAD_ENVIRONMENT:
        return EINVAL;
    case ERROR_BAD_EXE_FORMAT:
        return ENOEXEC;
    default:
        return EIO;
    }
}

static int errno_of_status(NTSTATUS status) {
    last_error = (DWORD) status;
    switch (status) {
    case STATUS_OBJECT_NAME_NOT_FOUND_:
    case STATUS_OBJECT_PATH_NOT_FOUND_:
        return ENOENT;
    case STATUS_OBJECT_NAME_COLLISION_:
        return EEXIST;
    case STATUS_FILE_IS_A_DIRECTORY_:
        return EISDIR;
    case STATUS_NOT_A_DIRECTORY_:
        return ENOTDIR;
    case STATUS_ACCESS_DENIED_:
        return EACCES;
    default:
        return errno_of(RtlNtStatusToDosError(status));
    }
}

/* ---- Strings ---- */

/* UTF-8 to a new UTF-16 string, or NULL. Refuses invalid UTF-8. */
static wchar_t *wide(const char *text) {
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *out = malloc((size_t) n * sizeof(wchar_t));
    if (out && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, out, n) != n) {
        free(out);
        out = NULL;
    }
    return out;
}

/* UTF-16 to UTF-8 into out (size bytes); "" when it does not fit. */
static void narrow(const wchar_t *text, char *out, int size) {
    if (WideCharToMultiByte(CP_UTF8, 0, text, -1, out, size, NULL, NULL) <= 0) out[0] = 0;
}

static int is_separator(wchar_t c) { return c == L'\\' || c == L'/'; }

/* Case-insensitive equality of n characters. */
static int same(const wchar_t *a, const wchar_t *b, size_t n) {
    return n == 0 || CompareStringOrdinal(a, (int) n, b, (int) n, TRUE) == CSTR_EQUAL;
}

/* Whether path is base or under it: a prefix ending at a separator. */
static int under(const wchar_t *path, const wchar_t *base) {
    size_t n = wcslen(base), m = wcslen(path);
    if (m < n || !same(path, base, n)) return 0;
    return m == n || (n > 0 && is_separator(base[n - 1])) || is_separator(path[n]);
}

/*
 * An absolute drive (C:\...) or UNC (\\server\share\...) path made full
 * (".", ".." and repeated separators resolved), without a trailing
 * separator except a drive's root. Refuses device and \\?\ forms, relative
 * paths and a colon past the drive (alternate data streams). Returns a new
 * string or NULL with *error set.
 */
static wchar_t *full_path(const wchar_t *path, int *error) {
    *error = EINVAL;
    size_t n = wcslen(path);
    int drive = n >= 3 && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
                path[1] == L':' && is_separator(path[2]);
    int unc = n >= 3 && is_separator(path[0]) && is_separator(path[1]) && path[2] != L'?' && path[2] != L'.';
    if (!drive && !unc) return NULL;
    for (size_t i = 2; i < n; i++) {
        if (path[i] == L':' || path[i] == L'*' || path[i] == L'?' || path[i] == L'"' || path[i] == L'<' ||
            path[i] == L'>' || path[i] == L'|' || path[i] < 32) {
            return NULL;
        }
    }
    DWORD size = GetFullPathNameW(path, 0, NULL, NULL);
    if (size == 0 || size > WPATH_MAX) {
        *error = size ? ENAMETOOLONG : errno_of(GetLastError());
        return NULL;
    }
    wchar_t *full = malloc(size * sizeof(wchar_t));
    if (!full) {
        *error = ENOMEM;
        return NULL;
    }
    DWORD got = GetFullPathNameW(path, size, full, NULL);
    if (got == 0 || got >= size) {
        free(full);
        *error = EIO;
        return NULL;
    }
    size_t length = wcslen(full);
    size_t keep = drive ? 3 : 2;
    while (length > keep && is_separator(full[length - 1])) full[--length] = 0;
    return full;
}

/* The final path of an open handle, normalised (\\?\C:\... or \\?\UNC\...). Returns a new string or NULL. */
static wchar_t *final_path(HANDLE handle) {
    DWORD size = GetFinalPathNameByHandleW(handle, NULL, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (size == 0 || size > WPATH_MAX) return NULL;
    wchar_t *out = malloc((size + 1) * sizeof(wchar_t));
    if (!out) return NULL;
    DWORD got = GetFinalPathNameByHandleW(handle, out, size + 1, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (got == 0 || got > size) {
        free(out);
        return NULL;
    }
    size_t length = wcslen(out);
    while (length > 7 && is_separator(out[length - 1])) out[--length] = 0;
    return out;
}

/* The final path of a folder named by path, or NULL. */
static wchar_t *final_path_of(const wchar_t *path) {
    HANDLE handle = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (handle == INVALID_HANDLE_VALUE) return NULL;
    wchar_t *out = final_path(handle);
    CloseHandle(handle);
    return out;
}

/* ---- The policy ---- */

struct rule {
    wchar_t *path;  /* full, as full_path makes it */
    unsigned mode;
};

struct sbx_policy {
    struct rule *rules;
    unsigned count;
    sbx_decide_fn decide;
    void *decide_context;
    sbx_audit_fn audit;
    void *audit_context;
};

static void log_refusal(void *context, const struct sbx_access *access, int result) {
    (void) context;
    if (result != 0) {
        fprintf(stderr, "sbx: refused %s %s (%s): %s\n", access->op, access->asked, access->resolved, strerror(-result));
    }
}

struct sbx_policy *sbx_policy_new(void) {
    struct sbx_policy *policy = calloc(1, sizeof(*policy));
    if (policy) policy->audit = log_refusal;
    return policy;
}

void sbx_policy_free(struct sbx_policy *policy) {
    if (!policy) return;
    for (unsigned i = 0; i < policy->count; i++) free(policy->rules[i].path);
    free(policy->rules);
    free(policy);
}

int sbx_policy_add(struct sbx_policy *policy, const char *path, unsigned mode) {
    if (!policy || !path) return -EINVAL;
    if ((mode & SBX_STATIC) && (mode & SBX_WRITE)) return -EINVAL;
    wchar_t *given = wide(path);
    if (!given) return -EINVAL;
    int error = 0;
    wchar_t *full = full_path(given, &error);
    free(given);
    if (!full) return -error;
    struct rule *grown = realloc(policy->rules, (policy->count + 1) * sizeof(struct rule));
    if (!grown) {
        free(full);
        return -ENOMEM;
    }
    policy->rules = grown;
    policy->rules[policy->count].path = full;
    policy->rules[policy->count].mode = mode & MODE_BITS;
    policy->count++;
    return 0;
}

void sbx_policy_set_decider(struct sbx_policy *policy, sbx_decide_fn decide, void *context) {
    if (!policy) return;
    policy->decide = decide;
    policy->decide_context = context;
}

void sbx_policy_set_audit(struct sbx_policy *policy, sbx_audit_fn audit, void *context) {
    if (!policy) return;
    policy->audit = audit;
    policy->audit_context = context;
}

/* The longest rule covering path, or NULL. */
static const struct rule *rule_for(const struct sbx_policy *policy, const wchar_t *path) {
    const struct rule *best = NULL;
    size_t best_length = 0;
    for (unsigned i = 0; i < policy->count; i++) {
        size_t length = wcslen(policy->rules[i].path);
        if ((!best || length > best_length) && under(path, policy->rules[i].path)) {
            best = &policy->rules[i];
            best_length = length;
        }
    }
    return best;
}

/* ---- The broker ---- */

struct broker {
    struct sbx_policy *policy;
    HANDLE pipe;     /* the server end */
    HANDLE process;  /* the program, for DuplicateHandle */
    DWORD pid;
};

/* The access the program's handle carries. */
static ACCESS_MASK access_for(unsigned flags) {
    if (flags & SBX_OPEN_DIRECTORY) return FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    ACCESS_MASK access = SYNCHRONIZE;
    if (flags & SBX_OPEN_READ) access |= FILE_GENERIC_READ;
    if (flags & SBX_OPEN_WRITE) {
        access |= FILE_GENERIC_WRITE;
        /* Without FILE_WRITE_DATA every write goes to the end. */
        if (flags & SBX_OPEN_APPEND) access &= ~(ACCESS_MASK) FILE_WRITE_DATA;
    }
    return access;
}

static ULONG disposition_for(unsigned flags) {
    if (flags & SBX_OPEN_CREATE) {
        if (flags & SBX_OPEN_EXCLUSIVE) return FILE_CREATE;
        return (flags & SBX_OPEN_TRUNCATE) ? FILE_OVERWRITE_IF : FILE_OPEN_IF;
    }
    return (flags & SBX_OPEN_TRUNCATE) ? FILE_OVERWRITE : FILE_OPEN;
}

static int valid_flags(unsigned flags) {
    if (flags & ~ALL_OPEN) return 0;
    if (flags & SBX_OPEN_DIRECTORY) return !(flags & WRITING);
    if (!(flags & (SBX_OPEN_READ | SBX_OPEN_WRITE))) return 0;
    if ((flags & (SBX_OPEN_TRUNCATE | SBX_OPEN_APPEND)) && !(flags & SBX_OPEN_WRITE)) return 0;
    if ((flags & SBX_OPEN_EXCLUSIVE) && !(flags & SBX_OPEN_CREATE)) return 0;
    return 1;
}

/* Opens leaf relative to folder; follow: whether a reparse point is followed. */
static NTSTATUS open_relative(HANDLE folder, const wchar_t *leaf, ACCESS_MASK access, ULONG disposition,
                              ULONG options, int follow, HANDLE *out) {
    UNICODE_STRING name;
    size_t bytes = wcslen(leaf) * sizeof(wchar_t);
    name.Length = (USHORT) bytes;
    name.MaximumLength = (USHORT) bytes;
    name.Buffer = (PWSTR) leaf;
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, folder, NULL);
    IO_STATUS_BLOCK status_block;
    memset(&status_block, 0, sizeof(status_block));
    options |= FILE_SYNCHRONOUS_IO_NONALERT;
    if (!follow) options |= FILE_OPEN_REPARSE_POINT;
    return NtCreateFile(out, access | SYNCHRONIZE | FILE_READ_ATTRIBUTES, &attributes, &status_block, NULL,
                        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, disposition,
                        options, NULL, 0);
}

static int is_reparse_point(HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO tag;
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag))) return 1;
    return (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

/* Whether handle's final path lies under the final path root_final. */
static int inside(HANDLE handle, const wchar_t *root_final) {
    wchar_t *final = final_path(handle);
    int ok = final && under(final, root_final);
    free(final);
    return ok;
}

/*
 * The open itself, under the broker's identity, once allowed. bound is the
 * folder every step must stay under: the rule's, or for a path the decider
 * granted without one, the path's own folder. Returns 0 and *out, or a
 * negative errno.
 */
static int open_contained(const wchar_t *full, const wchar_t *bound, unsigned flags, HANDLE *out) {
    wchar_t *bound_final = final_path_of(bound);
    if (!bound_final) return -errno_of(GetLastError());
    int result = 0;
    HANDLE folder = INVALID_HANDLE_VALUE, handle = NULL;
    wchar_t *parent = _wcsdup(full);
    if (!parent) {
        free(bound_final);
        return -ENOMEM;
    }
    wchar_t *cut = wcsrchr(parent, L'\\');
    const wchar_t *leaf = cut ? cut + 1 : L"";
    if (!cut || *leaf == 0) {
        /* A drive's or share's root: only as a folder, and only when the bound is the root itself. */
        result = -EACCES;
        goto done;
    }
    *cut = 0;
    if (cut == parent + 2 && parent[1] == L':') {
        cut[0] = L'\\';
        cut[1] = 0;
        leaf = full + 3;
    } else {
        leaf = full + (cut - parent) + 1;
    }
    folder = CreateFileW(parent, FILE_TRAVERSE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (folder == INVALID_HANDLE_VALUE) {
        result = -errno_of(GetLastError());
        goto done;
    }
    /*
     * A junction or symlink above the leaf that leads out of the bound.
     * When the path is the bound itself (a rule's own folder), its parent
     * lies outside, and only the handle's own final path is checked below.
     */
    int is_bound = wcslen(full) == wcslen(bound) && same(full, bound, wcslen(full));
    if (!is_bound && !inside(folder, bound_final)) {
        result = -EACCES;
        goto done;
    }
    ACCESS_MASK access = access_for(flags);
    ULONG options = (flags & SBX_OPEN_DIRECTORY) ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE;
    NTSTATUS status = open_relative(folder, leaf, access, disposition_for(flags), options, 0, &handle);
    if (!NT_SUCCESS(status)) {
        handle = NULL;
        result = -errno_of_status(status);
        goto done;
    }
    if (is_reparse_point(handle)) {
        CloseHandle(handle);
        handle = NULL;
        /* A link at the leaf is followed for reading only, and only to a place inside the bound. */
        if (flags & WRITING) {
            result = -EACCES;
            goto done;
        }
        status = open_relative(folder, leaf, access, FILE_OPEN, options, 1, &handle);
        if (!NT_SUCCESS(status)) {
            handle = NULL;
            result = -errno_of_status(status);
            goto done;
        }
    }
    if (!inside(handle, bound_final)) {
        result = -EACCES;
        goto done;
    }
    *out = handle;
    handle = NULL;
done:
    if (handle) CloseHandle(handle);
    if (folder != INVALID_HANDLE_VALUE) CloseHandle(folder);
    free(parent);
    free(bound_final);
    return result;
}

/* Answers one open request: 0 and the handle in the program, or a negative errno. */
static int answer_open(struct broker *broker, const char *asked, unsigned flags, uint64_t *remote) {
    struct sbx_policy *policy = broker->policy;
    char resolved[3 * SBXW_PATH_MAX] = "";
    struct sbx_access access = {"open", asked, resolved, 0, (int) flags, (pid_t) broker->pid, 0};
    int result;
    wchar_t *full = NULL;
    if (!valid_flags(flags)) {
        result = -EINVAL;
        goto report;
    }
    access.need = (flags & WRITING) ? SBX_WRITE : SBX_READ;
    wchar_t *given = wide(asked);
    int error = EINVAL;
    full = given ? full_path(given, &error) : NULL;
    free(given);
    if (!full) {
        result = -error;
        goto report;
    }
    narrow(full, resolved, (int) sizeof(resolved));
    const struct rule *rule = rule_for(policy, full);
    unsigned mode = rule ? rule->mode : SBX_DENY;
    access.rule_verdict = (mode & access.need) == access.need ? 0 : -EACCES;
    result = access.rule_verdict;
    if (policy->decide && (result != 0 || (mode & SBX_DECIDE))) {
        int decided = policy->decide(policy->decide_context, &access);
        if (decided != SBX_KEEP) result = decided > 0 ? -EACCES : decided;
    }
    if (result == 0) {
        /* The bound: the rule's folder when the rules allowed it, else the path's own folder. */
        wchar_t *bound = NULL;
        if (access.rule_verdict == 0) {
            bound = _wcsdup(rule->path);
        } else {
            bound = _wcsdup(full);
            wchar_t *cut = bound ? wcsrchr(bound, L'\\') : NULL;
            if (cut && cut > bound + 2) *cut = 0;
        }
        if (!bound) {
            result = -ENOMEM;
            goto report;
        }
        HANDLE handle = NULL;
        result = open_contained(full, bound, flags, &handle);
        free(bound);
        if (result == 0) {
            HANDLE theirs = NULL;
            if (DuplicateHandle(GetCurrentProcess(), handle, broker->process, &theirs, access_for(flags), FALSE,
                                DUPLICATE_CLOSE_SOURCE)) {
                *remote = (uint64_t) (uintptr_t) theirs;
            } else {
                result = -errno_of(GetLastError());
            }
        }
    }
report:
    free(full);
    if (policy->audit) policy->audit(policy->audit_context, &access, result);
    return result;
}

static DWORD WINAPI serve(void *argument) {
    struct broker *broker = argument;
    struct sbxw_request *request = malloc(sizeof(*request));
    for (;;) {
        DWORD got = 0;
        if (!request) break;
        BOOL read = ReadFile(broker->pipe, request, sizeof(*request), &got, NULL);
        struct sbxw_reply reply = {0, 0, 0};
        if (!read) {
            if (GetLastError() != ERROR_MORE_DATA) break; /* the program closed its end */
            /* An oversized message: drain it, then refuse. */
            char rest[512];
            DWORD more = 0;
            while (!ReadFile(broker->pipe, rest, sizeof(rest), &more, NULL) && GetLastError() == ERROR_MORE_DATA) {
            }
            reply.result = -ENAMETOOLONG;
        } else if (got < SBXW_HEADER || request->version != SBXW_VERSION || request->op != SBXW_OPEN ||
                   request->length == 0 || request->length > SBXW_PATH_MAX || got != SBXW_HEADER + request->length ||
                   request->path[request->length - 1] != 0 || strlen(request->path) + 1 != request->length) {
            reply.result = -EINVAL;
        } else {
            reply.result = answer_open(broker, request->path, request->flags, &reply.handle);
        }
        DWORD wrote = 0;
        if (!WriteFile(broker->pipe, &reply, sizeof(reply), &wrote, NULL)) break;
    }
    free(request);
    CloseHandle(broker->pipe);
    CloseHandle(broker->process);
    sbx_policy_free(broker->policy);
    free(broker);
    return 0;
}

/*
 * A message-mode pipe with one instance under a random name, connected to
 * itself at once: *server for the broker, *client (inheritable) for the
 * program. Nobody can connect to it by name afterwards.
 */
static int make_channel(HANDLE *server, HANDLE *client) {
    static volatile LONG counter;
    wchar_t name[128];
    unsigned long long random = 0;
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    random = (unsigned long long) now.QuadPart ^ ((unsigned long long) GetCurrentProcessId() << 32) ^
             ((unsigned long long) (uintptr_t) &now);
    swprintf(name, 128, L"\\\\.\\pipe\\sbx-%lu-%ld-%llx", GetCurrentProcessId(), InterlockedIncrement(&counter),
             random);
    *server = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                               PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
                               sizeof(struct sbxw_reply) * 4, sizeof(struct sbxw_request), 0, NULL);
    if (*server == INVALID_HANDLE_VALUE) return -errno_of(GetLastError());
    SECURITY_ATTRIBUTES inherit = {sizeof(inherit), NULL, TRUE};
    *client = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, &inherit, OPEN_EXISTING,
                          SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (*client == INVALID_HANDLE_VALUE) {
        int error = -errno_of(GetLastError());
        CloseHandle(*server);
        return error;
    }
    if (!ConnectNamedPipe(*server, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        int error = -errno_of(GetLastError());
        CloseHandle(*client);
        CloseHandle(*server);
        return error;
    }
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(*client, &mode, NULL, NULL);
    return 0;
}

/* ---- Spawn ---- */

/* Whether the system has less-privileged AppContainers (Windows 10 1703, build 15063). */
static int has_less_privileged(void) {
    typedef LONG(WINAPI * get_version_fn)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    get_version_fn get_version = ntdll ? (get_version_fn) (void (*)(void)) GetProcAddress(ntdll, "RtlGetVersion") : NULL;
    RTL_OSVERSIONINFOW version;
    memset(&version, 0, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    if (!get_version || get_version(&version) != 0) return 0;
    return version.dwMajorVersion > 10 || (version.dwMajorVersion == 10 && version.dwBuildNumber >= 15063);
}

/* The container's SID, its profile created when missing. */
static int container_sid(const char *container, PSID *sid) {
    wchar_t *name = wide(container);
    if (!name || !name[0] || wcslen(name) > 64) {
        free(name);
        return -EINVAL;
    }
    HRESULT made = CreateAppContainerProfile(name, name, name, NULL, 0, sid);
    if (made == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) made = DeriveAppContainerSidFromAppContainerName(name, sid);
    free(name);
    if (FAILED(made)) return made == E_ACCESSDENIED ? -EACCES : -ENOSYS;
    return 0;
}

#define STATIC_RIGHTS (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)
#define STATIC_INHERIT (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)

/* Whether dacl already grants sid the static rights, inherited. */
static int already_granted(PACL dacl, PSID sid) {
    if (!dacl) return 0;
    for (DWORD i = 0; i < dacl->AceCount; i++) {
        ACCESS_ALLOWED_ACE *ace = NULL;
        if (!GetAce(dacl, i, (void **) &ace) || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        if ((ace->Header.AceFlags & INHERITED_ACE) || (ace->Header.AceFlags & STATIC_INHERIT) != STATIC_INHERIT) continue;
        if ((ace->Mask & STATIC_RIGHTS) == STATIC_RIGHTS && EqualSid((PSID) &ace->SidStart, sid)) return 1;
    }
    return 0;
}

/* Grants the container read and execute on path and everything under it, unless it has them already. */
static int grant_static(const wchar_t *path, PSID sid) {
    PACL dacl = NULL, granted = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD error = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL,
                                        &descriptor);
    if (error != ERROR_SUCCESS) return -errno_of(error);
    if (already_granted(dacl, sid)) {
        LocalFree(descriptor);
        return 0;
    }
    EXPLICIT_ACCESS_W entry;
    memset(&entry, 0, sizeof(entry));
    entry.grfAccessPermissions = STATIC_RIGHTS;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    entry.Trustee.ptstrName = (LPWSTR) sid;
    error = SetEntriesInAclW(1, &entry, dacl, &granted);
    if (error == ERROR_SUCCESS) {
        error = SetNamedSecurityInfoW((LPWSTR) path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, granted,
                                      NULL);
    }
    LocalFree(granted);
    LocalFree(descriptor);
    return error == ERROR_SUCCESS ? 0 : -errno_of(error);
}

/* Appends text to a growing wide buffer. */
struct text {
    wchar_t *data;
    size_t length, capacity;
};

static int append(struct text *text, const wchar_t *more, size_t n) {
    if (text->length + n + 2 > text->capacity) {
        size_t capacity = (text->length + n + 2) * 2;
        wchar_t *grown = realloc(text->data, capacity * sizeof(wchar_t));
        if (!grown) return -ENOMEM;
        text->data = grown;
        text->capacity = capacity;
    }
    memcpy(text->data + text->length, more, n * sizeof(wchar_t));
    text->length += n;
    text->data[text->length] = 0;
    return 0;
}

/* Appends one argument quoted the way CommandLineToArgvW and the C runtime read it. */
static int append_argument(struct text *line, const wchar_t *argument) {
    if (line->length && append(line, L" ", 1)) return -ENOMEM;
    if (argument[0] && !wcspbrk(argument, L" \t\n\v\"")) return append(line, argument, wcslen(argument));
    if (append(line, L"\"", 1)) return -ENOMEM;
    for (const wchar_t *c = argument;; c++) {
        size_t slashes = 0;
        while (*c == L'\\') {
            c++;
            slashes++;
        }
        if (*c == 0) {
            for (size_t i = 0; i < slashes * 2; i++) {
                if (append(line, L"\\", 1)) return -ENOMEM;
            }
            break;
        }
        size_t count = *c == L'"' ? slashes * 2 + 1 : slashes;
        for (size_t i = 0; i < count; i++) {
            if (append(line, L"\\", 1)) return -ENOMEM;
        }
        if (append(line, c, 1)) return -ENOMEM;
    }
    return append(line, L"\"", 1);
}

static int command_line(char *const *argv, struct text *line) {
    for (char *const *argument = argv; *argument; argument++) {
        wchar_t *w = wide(*argument);
        if (!w) return -EINVAL;
        int error = append_argument(line, w);
        free(w);
        if (error) return error;
    }
    return line->length ? 0 : -EINVAL;
}

/*
 * Variables Windows reads to set up an AppContainer process (its own
 * LocalAppData and temporary folder are made from them; CreateProcess
 * fails with ERROR_ENVVAR_NOT_FOUND without them). Taken from the parent
 * when envp does not set them: they name folders and grant nothing.
 */
static const wchar_t *const container_variables[] = {
    L"SystemRoot", L"SystemDrive", L"USERPROFILE", L"LOCALAPPDATA", L"APPDATA", L"TEMP", L"TMP",
};

/* Whether envp sets name. */
static int sets(char *const *envp, const wchar_t *name) {
    size_t n = wcslen(name);
    for (char *const *entry = envp; envp && *entry; entry++) {
        wchar_t *w = wide(*entry);
        int found = w && wcslen(w) > n && w[n] == L'=' && same(w, name, n);
        free(w);
        if (found) return 1;
    }
    return 0;
}

/* The environment block: envp, the container's variables it lacks, then SBX_BROKER=<channel>. Double-NUL terminated. */
static int environment(char *const *envp, HANDLE channel, struct text *block) {
    if (envp) {
        for (char *const *entry = envp; *entry; entry++) {
            wchar_t *w = wide(*entry);
            if (!w || !wcschr(w, L'=') || w[0] == L'=') {
                free(w);
                return -EINVAL;
            }
            int error = append(block, w, wcslen(w) + 1);
            free(w);
            if (error) return error;
        }
    }
    for (size_t i = 0; i < sizeof(container_variables) / sizeof(container_variables[0]); i++) {
        const wchar_t *name = container_variables[i];
        if (sets(envp, name)) continue;
        wchar_t value[MAX_PATH];
        DWORD n = GetEnvironmentVariableW(name, value, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) continue;
        if (append(block, name, wcslen(name)) || append(block, L"=", 1) || append(block, value, (size_t) n + 1)) {
            return -ENOMEM;
        }
    }
    if (channel) {
        wchar_t entry[64];
        int n = swprintf(entry, 64, L"%ls=%llu", SBXW_ENV, (unsigned long long) (uintptr_t) channel);
        if (n < 0 || append(block, entry, (size_t) n + 1)) return -ENOMEM;
    }
    if (append(block, L"\0", 1)) return -ENOMEM;
    if (block->length == 1 && append(block, L"\0", 1)) return -ENOMEM;
    return 0;
}

static int inheritable(HANDLE handle) {
    DWORD flags = 0;
    return handle && handle != INVALID_HANDLE_VALUE && GetHandleInformation(handle, &flags) &&
           (flags & HANDLE_FLAG_INHERIT);
}

/* Adds handle to list unless it is there already. */
static void list_add(HANDLE *list, unsigned *count, HANDLE handle) {
    for (unsigned i = 0; i < *count; i++) {
        if (list[i] == handle) return;
    }
    list[(*count)++] = handle;
}

static HANDLE make_job(unsigned long long memory_limit) {
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (!job) return NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    if (memory_limit) {
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limits.ProcessMemoryLimit = (SIZE_T) memory_limit;
    }
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui;
    ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                             JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS |
                             JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD |
                             JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
        !SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui))) {
        CloseHandle(job);
        return NULL;
    }
    return job;
}

int sbx_spawn(const struct sbx_spawn_spec *spec, struct sbx_process *out) {
    struct sbx_policy *policy = spec ? spec->policy : NULL;
    int result = 0;
    PSID sid = NULL;
    HANDLE job = NULL, server = NULL, client = NULL;
    wchar_t *path = NULL;
    struct text line = {0}, block = {0};
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    PROCESS_INFORMATION info;
    memset(&info, 0, sizeof(info));
    HANDLE list[SBX_SPAWN_HANDLES_MAX + 4];
    unsigned list_count = 0;

    if (out) memset(out, 0, sizeof(*out));
    last_error = 0;
    if (!spec || !out || !spec->path || !spec->argv || !spec->argv[0] || !spec->container ||
        spec->handle_count > SBX_SPAWN_HANDLES_MAX || (spec->handle_count && !spec->handles)) {
        result = -EINVAL;
        goto fail;
    }
    for (unsigned i = 0; i < spec->handle_count; i++) {
        if (!inheritable(spec->handles[i])) {
            result = -EINVAL;
            goto fail;
        }
        list_add(list, &list_count, spec->handles[i]);
    }
    HANDLE std[3] = {spec->std_in, spec->std_out, spec->std_err};
    for (int i = 0; i < 3; i++) {
        if (!std[i]) continue;
        if (!inheritable(std[i])) {
            result = -EINVAL;
            goto fail;
        }
        list_add(list, &list_count, std[i]);
    }
    path = wide(spec->path);
    if (!path) {
        result = -EINVAL;
        goto fail;
    }
    result = command_line(spec->argv, &line);
    if (result) goto fail;

    /* The container, and its static grants. */
    result = container_sid(spec->container, &sid);
    if (result) goto fail;
    if (policy) {
        for (unsigned i = 0; i < policy->count; i++) {
            if (!(policy->rules[i].mode & SBX_STATIC)) continue;
            result = grant_static(policy->rules[i].path, sid);
            if (result) goto fail;
        }
        result = make_channel(&server, &client);
        if (result) goto fail;
        list_add(list, &list_count, client);
    }
    result = environment(spec->envp, client, &block);
    if (result) goto fail;
    job = make_job(spec->memory_limit);
    if (!job) {
        result = -errno_of(GetLastError());
        goto fail;
    }

    /* The process-creation attributes: container, handle list, no children, LPAC. */
    int less = spec->less_privileged && has_less_privileged();
    DWORD count = 2 + (list_count ? 1 : 0) + (less ? 1 : 0);
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(NULL, count, 0, &size);
    attributes = malloc(size);
    if (!attributes || !InitializeProcThreadAttributeList(attributes, count, 0, &size)) {
        free(attributes);
        attributes = NULL;
        result = -ENOMEM;
        goto fail;
    }
    SECURITY_CAPABILITIES capabilities;
    memset(&capabilities, 0, sizeof(capabilities));
    capabilities.AppContainerSid = sid;
    DWORD child_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
    DWORD packages_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities,
                                   sizeof(capabilities), NULL, NULL) ||
        !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &child_policy,
                                   sizeof(child_policy), NULL, NULL) ||
        (list_count && !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list,
                                                  list_count * sizeof(HANDLE), NULL, NULL)) ||
        (less && !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                                            &packages_policy, sizeof(packages_policy), NULL, NULL))) {
        result = -errno_of(GetLastError());
        goto fail;
    }
    STARTUPINFOEXW startup;
    memset(&startup, 0, sizeof(startup));
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = spec->std_in;
    startup.StartupInfo.hStdOutput = spec->std_out;
    startup.StartupInfo.hStdError = spec->std_err;
    startup.lpAttributeList = attributes;
    if (!CreateProcessW(path, line.data, NULL, NULL, list_count ? TRUE : FALSE,
                        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                        block.data, NULL, &startup.StartupInfo, &info)) {
        result = -errno_of(GetLastError());
        goto fail;
    }
    /* Into the job before it runs a single instruction of its own. */
    if (!AssignProcessToJobObject(job, info.hProcess)) {
        result = -errno_of(GetLastError());
        TerminateProcess(info.hProcess, 1);
        goto fail;
    }
    if (policy) {
        struct broker *broker = calloc(1, sizeof(*broker));
        HANDLE process = NULL;
        if (!broker || !DuplicateHandle(GetCurrentProcess(), info.hProcess, GetCurrentProcess(), &process,
                                        PROCESS_DUP_HANDLE, FALSE, 0)) {
            free(broker);
            result = broker ? -errno_of(GetLastError()) : -ENOMEM;
            TerminateProcess(info.hProcess, 1);
            goto fail;
        }
        broker->policy = policy;
        broker->pipe = server;
        broker->process = process;
        broker->pid = info.dwProcessId;
        HANDLE thread = CreateThread(NULL, 0, serve, broker, 0, NULL);
        if (!thread) {
            result = -errno_of(GetLastError());
            CloseHandle(process);
            free(broker);
            TerminateProcess(info.hProcess, 1);
            goto fail;
        }
        CloseHandle(thread);
        policy = NULL;
        server = NULL;
    }
    if (ResumeThread(info.hThread) == (DWORD) -1) {
        result = -errno_of(GetLastError());
        TerminateProcess(info.hProcess, 1);
        goto fail;
    }
    CloseHandle(info.hThread);
    info.hThread = NULL;
    out->process = info.hProcess;
    out->job = job;
    out->pid = info.dwProcessId;
    out->less_privileged = less;
    info.hProcess = NULL;
    job = NULL;
    result = 0;
fail:
    if (info.hThread) CloseHandle(info.hThread);
    if (info.hProcess) CloseHandle(info.hProcess);
    if (job) CloseHandle(job); /* kills a program that was started */
    if (client) CloseHandle(client); /* the program holds its own copy */
    if (server) CloseHandle(server);
    if (attributes) {
        DeleteProcThreadAttributeList(attributes);
        free(attributes);
    }
    if (sid) FreeSid(sid);
    free(path);
    free(line.data);
    free(block.data);
    sbx_policy_free(policy);
    return result;
}

int sbx_process_wait(struct sbx_process *process, int *exit_code) {
    if (!process || !process->process) return -EINVAL;
    int result = 0;
    DWORD code = 0;
    if (WaitForSingleObject(process->process, INFINITE) != WAIT_OBJECT_0 || !GetExitCodeProcess(process->process, &code)) {
        result = -errno_of(GetLastError());
    }
    if (exit_code) *exit_code = (int) code;
    sbx_process_close(process);
    return result;
}

void sbx_process_close(struct sbx_process *process) {
    if (!process) return;
    if (process->job) CloseHandle(process->job);
    if (process->process) CloseHandle(process->process);
    process->job = NULL;
    process->process = NULL;
}
