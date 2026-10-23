/*
 * The Windows escape suite. The test starts itself twice as a child that
 * runs the same attempts: unconfined, as a control in which each must
 * succeed (otherwise it proves nothing), then under sbx_spawn, where each
 * must fail. The confined child then checks what the broker must allow and
 * refuse. Children print one line per result; the parent judges.
 *
 *   attempt <name> <0 for success, else the error>
 *   check <name> <1 or 0>
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winternl.h>

#include "sbx.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CONTAINER "sbx-test"
#define MEMORY_LIMIT (256ull << 20)

static int failures;

#define EXPECT(condition, what)                                                                    \
    do {                                                                                           \
        if (condition) {                                                                           \
            printf("ok   %s\n", what);                                                             \
        } else {                                                                                   \
            printf("FAIL %s\n", what);                                                             \
            failures++;                                                                            \
        }                                                                                          \
        fflush(stdout);                                                                            \
    } while (0)

/* ---- In the child: what it is given ---- */

static wchar_t root[MAX_PATH], profile[MAX_PATH], exe_dir[MAX_PATH], exe_path[MAX_PATH];
static unsigned short port;
static DWORD parent_pid;

static void child_path(wchar_t *out, const wchar_t *relative) {
    swprintf(out, MAX_PATH, L"%ls\\%ls", root, relative);
}

static int last_error(void) {
    DWORD error = GetLastError();
    return error ? (int) error : -1;
}

static int a_read_secret(void) {
    wchar_t path[MAX_PATH];
    child_path(path, L"secret\\key");
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return last_error();
    CloseHandle(file);
    return 0;
}

static int a_write_save(void) {
    wchar_t path[MAX_PATH];
    child_path(path, L"save\\direct.txt");
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return last_error();
    CloseHandle(file);
    DeleteFileW(path);
    return 0;
}

static int a_list_profile(void) {
    wchar_t pattern[MAX_PATH];
    swprintf(pattern, MAX_PATH, L"%ls\\*", profile);
    WIN32_FIND_DATAW data;
    HANDLE find = FindFirstFileW(pattern, &data);
    if (find == INVALID_HANDLE_VALUE) return last_error();
    FindClose(find);
    return 0;
}

static int a_write_static(void) {
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"%ls\\sbx-static-write.txt", exe_dir);
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return last_error();
    CloseHandle(file);
    DeleteFileW(path);
    return 0;
}

static int run_process(DWORD flags) {
    wchar_t command[MAX_PATH + 32], system[MAX_PATH];
    GetSystemDirectoryW(system, MAX_PATH);
    swprintf(command, MAX_PATH + 32, L"\"%ls\\cmd.exe\" /c exit 0", system);
    STARTUPINFOW startup;
    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION info;
    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, flags | CREATE_NO_WINDOW, NULL, NULL, &startup, &info)) {
        return last_error();
    }
    WaitForSingleObject(info.hProcess, 10000);
    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);
    return 0;
}

static int a_create_process(void) { return run_process(0); }
static int a_breakaway(void) { return run_process(CREATE_BREAKAWAY_FROM_JOB); }

static int a_connect(void) {
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return -2;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return WSAGetLastError();
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int result = connect(s, (struct sockaddr *) &address, sizeof(address)) == 0 ? 0 : WSAGetLastError();
    closesocket(s);
    return result;
}

static int a_registry(void) {
    HKEY key;
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\sbx-test-escape", 0, NULL, 0, KEY_WRITE, NULL, &key, NULL);
    if (result != ERROR_SUCCESS) return (int) result;
    RegCloseKey(key);
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\sbx-test-escape");
    return 0;
}

static int a_parent_memory(void) {
    HANDLE parent = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, parent_pid);
    if (!parent) return last_error();
    CloseHandle(parent);
    return 0;
}

static int a_named_event(void) {
    wchar_t name[64];
    swprintf(name, 64, L"Local\\sbx-test-%lu", parent_pid);
    HANDLE event = OpenEventW(SYNCHRONIZE, FALSE, name);
    if (!event) return last_error();
    CloseHandle(event);
    return 0;
}

static int a_clipboard(void) {
    if (!OpenClipboard(NULL)) return last_error();
    int result = EmptyClipboard() ? 0 : last_error();
    CloseClipboard();
    return result;
}

static int a_memory(void) {
    void *block = VirtualAlloc(NULL, (SIZE_T) (MEMORY_LIMIT * 2), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!block) return last_error();
    VirtualFree(block, 0, MEM_RELEASE);
    return 0;
}

struct attempt {
    const char *name;
    int (*run)(void);
    int host_may_refuse; /* the control may fail on a host that forbids it anyway */
};

static const struct attempt attempts[] = {
    {"read a file outside the rules by path", a_read_secret, 0},
    {"write a file in an allowed folder by path", a_write_save, 0},
    {"list the user's profile folder", a_list_profile, 0},
    {"write in the static read-only grant", a_write_static, 0},
    {"create a process", a_create_process, 0},
    {"create a process breaking away from the job", a_breakaway, 1},
    {"connect to a TCP port on 127.0.0.1", a_connect, 0},
    {"create a key under HKEY_CURRENT_USER\\Software", a_registry, 0},
    {"open the parent process to read its memory", a_parent_memory, 0},
    {"open a named event in the session's namespace", a_named_event, 0},
    {"write the clipboard", a_clipboard, 1},
    {"commit more memory than the job allows", a_memory, 0},
};
#define ATTEMPTS (sizeof(attempts) / sizeof(attempts[0]))

/* ---- In the confined child: the broker ---- */

static void check(const char *name, int ok) {
    printf("check %s|%d\n", name, ok ? 1 : 0);
    fflush(stdout);
}

static void utf8_path(char *out, size_t size, const wchar_t *relative) {
    wchar_t wpath[MAX_PATH];
    child_path(wpath, relative);
    if (WideCharToMultiByte(CP_UTF8, 0, wpath, -1, out, (int) size, NULL, NULL) <= 0) out[0] = 0;
}

static int read_word(HANDLE file, char *out, DWORD size) {
    DWORD got = 0;
    if (!ReadFile(file, out, size - 1, &got, NULL)) got = 0;
    out[got] = 0;
    return (int) got;
}

typedef NTSTATUS(NTAPI *nt_create_file_fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER,
                                           ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

static void broker_checks(void) {
    char path[MAX_PATH * 3], word[32];
    sbx_handle handle = NULL;

    wchar_t own[MAX_PATH];
    GetModuleFileNameW(NULL, own, MAX_PATH);
    HANDLE self = CreateFileW(own, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    check("the static grant lets the program read its own folder by path", self != INVALID_HANDLE_VALUE);
    if (self != INVALID_HANDLE_VALUE) CloseHandle(self);

    utf8_path(path, sizeof(path), L"game\\data.txt");
    int r = sbx_open(path, SBX_OPEN_READ, &handle);
    check("sbx_open of an allowed file", r == 0);
    if (r == 0) {
        read_word(handle, word, sizeof(word));
        check("and it reads", strcmp(word, "hello") == 0);
        HANDLE wider = NULL;
        check("DuplicateHandle cannot widen a read handle to write",
              !DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &wider, FILE_GENERIC_WRITE, FALSE, 0));
        if (wider) CloseHandle(wider);
        HANDLE reopened = ReOpenFile(handle, GENERIC_WRITE, FILE_SHARE_READ, 0);
        check("ReOpenFile cannot widen it either", reopened == INVALID_HANDLE_VALUE);
        if (reopened != INVALID_HANDLE_VALUE) CloseHandle(reopened);
        CloseHandle(handle);
    }

    utf8_path(path, sizeof(path), L"save\\new.txt");
    r = sbx_open(path, SBX_OPEN_WRITE | SBX_OPEN_CREATE | SBX_OPEN_TRUNCATE, &handle);
    check("sbx_open creates a file in a writable rule", r == 0);
    if (r == 0) {
        DWORD wrote = 0;
        check("and writes it", WriteFile(handle, "put", 3, &wrote, NULL) && wrote == 3);
        CloseHandle(handle);
        r = sbx_open(path, SBX_OPEN_READ, &handle);
        if (r == 0) {
            read_word(handle, word, sizeof(word));
            CloseHandle(handle);
        }
        check("which reads back", r == 0 && strcmp(word, "put") == 0);
    }
    check("SBX_OPEN_EXCLUSIVE refuses an existing file",
          sbx_open(path, SBX_OPEN_WRITE | SBX_OPEN_CREATE | SBX_OPEN_EXCLUSIVE, &handle) == -EEXIST);

    utf8_path(path, sizeof(path), L"secret\\key");
    check("sbx_open outside the rules is refused", sbx_open(path, SBX_OPEN_READ, &handle) == -EACCES);
    utf8_path(path, sizeof(path), L"game\\..\\secret\\key");
    check("sbx_open through \"..\" out of a rule is refused", sbx_open(path, SBX_OPEN_READ, &handle) == -EACCES);
    utf8_path(path, sizeof(path), L"game\\data.txt");
    check("sbx_open for writing in a read-only rule is refused", sbx_open(path, SBX_OPEN_WRITE, &handle) == -EACCES);
    utf8_path(path, sizeof(path), L"save\\link\\key");
    r = sbx_open(path, SBX_OPEN_READ, &handle);
    check("sbx_open through a junction leading out of a rule is refused", r == -EACCES);
    if (r == 0) CloseHandle(handle);
    utf8_path(path, sizeof(path), L"GAME\\DATA.TXT");
    r = sbx_open(path, SBX_OPEN_READ, &handle);
    check("rules match case-insensitively", r == 0);
    if (r == 0) CloseHandle(handle);
    utf8_path(path, sizeof(path), L"game\\data.txt:hidden");
    check("an alternate data stream is refused", sbx_open(path, SBX_OPEN_READ, &handle) == -EINVAL);
    check("a relative path is refused", sbx_open("data.txt", SBX_OPEN_READ, &handle) == -EINVAL);
    check("a device path is refused", sbx_open("\\\\.\\PhysicalDrive0", SBX_OPEN_READ, &handle) == -EINVAL);

    utf8_path(path, sizeof(path), L"game");
    r = sbx_open(path, SBX_OPEN_DIRECTORY, &handle);
    check("sbx_open of a rule's folder as a folder", r == 0);
    if (r == 0) {
        char listing[4096];
        check("it lists", GetFileInformationByHandleEx(handle, FileIdBothDirectoryRestartInfo, listing, sizeof(listing)));
        nt_create_file_fn nt_create_file =
            (nt_create_file_fn) (void (*)(void)) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");
        UNICODE_STRING name;
        wchar_t leaf[] = L"data.txt";
        name.Buffer = leaf;
        name.Length = (USHORT) (wcslen(leaf) * sizeof(wchar_t));
        name.MaximumLength = name.Length;
        OBJECT_ATTRIBUTES attributes;
        InitializeObjectAttributes(&attributes, &name, 0, handle, NULL);
        IO_STATUS_BLOCK status_block;
        HANDLE relative = NULL;
        NTSTATUS status = nt_create_file ? nt_create_file(&relative, FILE_GENERIC_READ, &attributes, &status_block,
                                                          NULL, 0, FILE_SHARE_READ, 1 /* FILE_OPEN */,
                                                          0x20 /* FILE_SYNCHRONOUS_IO_NONALERT */, NULL, 0)
                                         : 0;
        check("an open relative to a brokered folder handle is refused by the token", nt_create_file && status < 0);
        if (status >= 0 && relative) CloseHandle(relative);
        CloseHandle(handle);
    }
}

static int child_main(int confined) {
    for (size_t i = 0; i < ATTEMPTS; i++) {
        SetLastError(0);
        printf("attempt %s|%d\n", attempts[i].name, attempts[i].run());
        fflush(stdout);
    }
    if (confined) broker_checks();
    return 0;
}

/* ---- In the parent ---- */

struct result {
    char name[160];
    int value;
};

/* Reads every line the child writes, until it closes the pipe. */
static size_t collect(HANDLE pipe, struct result *attempt_results, size_t *attempt_count, struct result *checks,
                      size_t max) {
    static char buffer[65536];
    size_t used = 0;
    DWORD got = 0;
    while (used < sizeof(buffer) - 1 && ReadFile(pipe, buffer + used, (DWORD) (sizeof(buffer) - 1 - used), &got, NULL) &&
           got > 0) {
        used += got;
    }
    buffer[used] = 0;
    size_t check_count = 0;
    *attempt_count = 0;
    for (char *line = strtok(buffer, "\r\n"); line; line = strtok(NULL, "\r\n")) {
        int is_attempt = strncmp(line, "attempt ", 8) == 0, is_check = strncmp(line, "check ", 6) == 0;
        char *bar = strrchr(line, '|');
        if ((!is_attempt && !is_check) || !bar) {
            printf("     child: %s\n", line);
            continue;
        }
        *bar = 0;
        struct result *into = is_attempt ? &attempt_results[(*attempt_count)++] : &checks[check_count++];
        snprintf(into->name, sizeof(into->name), "%s", line + (is_attempt ? 8 : 6));
        into->value = atoi(bar + 1);
        if (*attempt_count >= max || check_count >= max) break;
    }
    return check_count;
}

static void make_file(const wchar_t *path, const char *text) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD wrote = 0;
    if (file != INVALID_HANDLE_VALUE) {
        WriteFile(file, text, (DWORD) strlen(text), &wrote, NULL);
        CloseHandle(file);
    }
}

static void to_utf8(char *out, size_t size, const wchar_t *text) {
    if (WideCharToMultiByte(CP_UTF8, 0, text, -1, out, (int) size, NULL, NULL) <= 0) out[0] = 0;
}

static int audit_refusals;
static void count_refusals(void *context, const struct sbx_access *access, int result) {
    (void) context;
    if (result != 0) {
        InterlockedIncrement((volatile LONG *) &audit_refusals);
        fprintf(stderr, "     audit: refused %s %s: %d\n", access->op, access->asked, result);
    }
}

int main(int argc, char **argv) {
    if (argc >= 8 && strcmp(argv[1], "--child") == 0) {
        MultiByteToWideChar(CP_UTF8, 0, argv[3], -1, root, MAX_PATH);
        MultiByteToWideChar(CP_UTF8, 0, argv[4], -1, profile, MAX_PATH);
        MultiByteToWideChar(CP_UTF8, 0, argv[5], -1, exe_dir, MAX_PATH);
        port = (unsigned short) atoi(argv[6]);
        parent_pid = (DWORD) strtoul(argv[7], NULL, 10);
        return child_main(strcmp(argv[2], "confined") == 0);
    }

    /* The places: a game folder (read), a save folder (write) with a junction leading out, a secret. */
    wchar_t temp[MAX_PATH], path[MAX_PATH], target[MAX_PATH];
    GetTempPathW(MAX_PATH, temp);
    swprintf(root, MAX_PATH, L"%lssbx-test-%lu", temp, GetCurrentProcessId());
    CreateDirectoryW(root, NULL);
    child_path(path, L"game");
    CreateDirectoryW(path, NULL);
    child_path(path, L"save");
    CreateDirectoryW(path, NULL);
    child_path(path, L"secret");
    CreateDirectoryW(path, NULL);
    child_path(path, L"game\\data.txt");
    make_file(path, "hello");
    child_path(path, L"secret\\key");
    make_file(path, "secret");
    child_path(path, L"save\\link");
    child_path(target, L"secret");
    wchar_t mklink[3 * MAX_PATH];
    swprintf(mklink, 3 * MAX_PATH, L"cmd.exe /c mklink /J \"%ls\" \"%ls\" >NUL", path, target);
    _wsystem(mklink);
    DWORD link_attributes = GetFileAttributesW(path);
    EXPECT(link_attributes != INVALID_FILE_ATTRIBUTES && (link_attributes & FILE_ATTRIBUTE_REPARSE_POINT),
           "the junction for the containment test exists");

    GetModuleFileNameW(NULL, exe_path, MAX_PATH);
    wcscpy(exe_dir, exe_path);
    *wcsrchr(exe_dir, L'\\') = 0;
    if (!GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH)) wcscpy(profile, L"C:\\Users");

    /* A listening port and a named event the child must not reach. */
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int length = sizeof(address);
    EXPECT(listener != INVALID_SOCKET && bind(listener, (struct sockaddr *) &address, sizeof(address)) == 0 &&
               listen(listener, 8) == 0 && getsockname(listener, (struct sockaddr *) &address, &length) == 0,
           "a listening port for the network attempt");
    port = ntohs(address.sin_port);
    wchar_t event_name[64];
    swprintf(event_name, 64, L"Local\\sbx-test-%lu", GetCurrentProcessId());
    HANDLE event = CreateEventW(NULL, FALSE, FALSE, event_name);
    EXPECT(event != NULL, "a named event for the named-object attempt");

    char root8[MAX_PATH * 3], profile8[MAX_PATH * 3], exe_dir8[MAX_PATH * 3], exe8[MAX_PATH * 3], port8[16], pid8[16];
    to_utf8(root8, sizeof(root8), root);
    to_utf8(profile8, sizeof(profile8), profile);
    to_utf8(exe_dir8, sizeof(exe_dir8), exe_dir);
    to_utf8(exe8, sizeof(exe8), exe_path);
    snprintf(port8, sizeof(port8), "%u", port);
    snprintf(pid8, sizeof(pid8), "%lu", GetCurrentProcessId());

    struct result control[64], confined[64], checks[64], unused[64];
    size_t control_count = 0, confined_count = 0, check_count = 0;
    SECURITY_ATTRIBUTES inherit = {sizeof(inherit), NULL, TRUE};

    /* The control: the same child, unconfined. */
    {
        HANDLE read_end, write_end;
        CreatePipe(&read_end, &write_end, &inherit, 0);
        SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);
        wchar_t command[4 * MAX_PATH];
        swprintf(command, 4 * MAX_PATH, L"\"%ls\" --child control \"%ls\" \"%ls\" \"%ls\" %u %lu", exe_path, root,
                 profile, exe_dir, port, GetCurrentProcessId());
        STARTUPINFOW startup;
        memset(&startup, 0, sizeof(startup));
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdOutput = write_end;
        startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        PROCESS_INFORMATION info;
        BOOL started = CreateProcessW(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &startup, &info);
        CloseHandle(write_end);
        EXPECT(started, "the control child starts");
        if (started) {
            collect(read_end, control, &control_count, unused, 64);
            WaitForSingleObject(info.hProcess, INFINITE);
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
        }
        CloseHandle(read_end);
    }

    /* Failing closed: a bad spec starts nothing. */
    {
        struct sbx_policy *bad = sbx_policy_new();
        EXPECT(sbx_policy_add(bad, exe8, SBX_READ | SBX_WRITE | SBX_STATIC) == -EINVAL,
               "a static grant that allows writing is refused");
        EXPECT(sbx_policy_add(bad, "relative\\path", SBX_READ) == -EINVAL, "a relative rule is refused");
        char *argv_missing[] = {"missing", NULL};
        struct sbx_spawn_spec spec;
        memset(&spec, 0, sizeof(spec));
        spec.path = "C:\\sbx-test-does-not-exist.exe";
        spec.argv = argv_missing;
        spec.container = CONTAINER;
        spec.policy = bad;
        struct sbx_process process;
        EXPECT(sbx_spawn(&spec, &process) < 0 && process.process == NULL, "a program that cannot start is an error");
        HANDLE plain = CreateEventW(NULL, FALSE, FALSE, NULL);
        spec.path = exe8;
        spec.policy = NULL;
        spec.handles = &plain;
        spec.handle_count = 1;
        EXPECT(sbx_spawn(&spec, &process) == -EINVAL, "a handle that is not inheritable is refused");
        CloseHandle(plain);
    }

    /* Confined. */
    {
        struct sbx_policy *policy = sbx_policy_new();
        char game8[MAX_PATH * 3], save8[MAX_PATH * 3];
        utf8_path(game8, sizeof(game8), L"game");
        utf8_path(save8, sizeof(save8), L"save");
        EXPECT(sbx_policy_add(policy, game8, SBX_READ) == 0 && sbx_policy_add(policy, save8, SBX_WRITE) == 0 &&
                   sbx_policy_add(policy, exe_dir8, SBX_READ | SBX_STATIC) == 0,
               "the policy");
        sbx_policy_set_audit(policy, count_refusals, NULL);
        HANDLE read_end, write_end;
        CreatePipe(&read_end, &write_end, &inherit, 0);
        SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);
        HANDLE error_out = NULL;
        DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_ERROR_HANDLE), GetCurrentProcess(), &error_out, 0, TRUE,
                        DUPLICATE_SAME_ACCESS);
        char *child_argv[] = {exe8, "--child", "confined", root8, profile8, exe_dir8, port8, pid8, NULL};
        wchar_t system_root[MAX_PATH];
        char system_root_entry[MAX_PATH * 3 + 16];
        GetEnvironmentVariableW(L"SystemRoot", system_root, MAX_PATH);
        snprintf(system_root_entry, sizeof(system_root_entry), "SystemRoot=");
        to_utf8(system_root_entry + 11, sizeof(system_root_entry) - 11, system_root);
        char *envp[] = {system_root_entry, NULL};
        struct sbx_spawn_spec spec;
        memset(&spec, 0, sizeof(spec));
        spec.path = exe8;
        spec.argv = child_argv;
        spec.envp = envp;
        spec.std_out = write_end;
        spec.std_err = error_out;
        spec.container = CONTAINER;
        spec.less_privileged = 1;
        spec.memory_limit = MEMORY_LIMIT;
        spec.policy = policy;
        struct sbx_process process;
        int spawned = sbx_spawn(&spec, &process);
        CloseHandle(write_end);
        if (error_out) CloseHandle(error_out);
        printf("     sbx_spawn: %d (Windows error %lu), less-privileged: %d\n", spawned, sbx_spawn_error(),
               spawned == 0 ? process.less_privileged : -1);
        EXPECT(spawned == 0, "the confined child starts");
        if (spawned == 0) {
            check_count = collect(read_end, confined, &confined_count, checks, 64);
            int code = -1;
            EXPECT(sbx_process_wait(&process, &code) == 0 && code == 0, "the confined child exits cleanly");
        }
        CloseHandle(read_end);
    }

    /* The judgement. */
    EXPECT(control_count == ATTEMPTS, "the control ran every attempt");
    EXPECT(confined_count == ATTEMPTS, "the confined child ran every attempt");
    for (size_t i = 0; i < ATTEMPTS; i++) {
        int control_value = i < control_count ? control[i].value : -1;
        int confined_value = i < confined_count ? confined[i].value : 0;
        char what[256];
        if (control_value != 0) {
            snprintf(what, sizeof(what), "control: %s succeeds unconfined (error %d)", attempts[i].name, control_value);
            if (attempts[i].host_may_refuse) {
                printf("skip %s (the host refuses it unconfined: %d)\n", attempts[i].name, control_value);
                continue;
            }
            EXPECT(0, what);
            continue;
        }
        snprintf(what, sizeof(what), "confined: %s refused (error %d)", attempts[i].name, confined_value);
        EXPECT(confined_value != 0, what);
    }
    EXPECT(check_count > 0, "the confined child ran the broker checks");
    for (size_t i = 0; i < check_count; i++) {
        char what[200];
        snprintf(what, sizeof(what), "broker: %s", checks[i].name);
        EXPECT(checks[i].value == 1, what);
    }
    EXPECT(audit_refusals >= 5, "the audit saw the broker's refusals");

    child_path(path, L"save\\new.txt");
    HANDLE written = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    char word[16] = "";
    if (written != INVALID_HANDLE_VALUE) {
        read_word(written, word, sizeof(word));
        CloseHandle(written);
    }
    EXPECT(strcmp(word, "put") == 0, "the file the child created through the broker holds what it wrote");

    /* Removes what it made, one by one (the junction itself, not what it leads to). */
    static const wchar_t *const files[] = {L"save\\new.txt", L"game\\data.txt", L"secret\\key"};
    static const wchar_t *const folders[] = {L"save\\link", L"save", L"game", L"secret"};
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        child_path(path, files[i]);
        DeleteFileW(path);
    }
    for (size_t i = 0; i < sizeof(folders) / sizeof(folders[0]); i++) {
        child_path(path, folders[i]);
        RemoveDirectoryW(path);
    }
    RemoveDirectoryW(root);
    if (event) CloseHandle(event);
    closesocket(listener);
    printf(failures ? "%d failure(s)\n" : "all passed\n", failures);
    return failures ? 1 : 0;
}
