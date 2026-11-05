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
#include <aclapi.h>
#include <userenv.h>
#include <sddl.h>

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

/*
 * Winsock and user32 are loaded when an attempt needs them, not imported:
 * the parent and both children are this one program, and a DLL that fails
 * to initialise in a container would end the child before main.
 */
static struct {
    int (WSAAPI *startup)(WORD, LPWSADATA);
    SOCKET (WSAAPI *socket)(int, int, int);
    int (WSAAPI *connect)(SOCKET, const struct sockaddr *, int);
    int (WSAAPI *bind)(SOCKET, const struct sockaddr *, int);
    int (WSAAPI *listen)(SOCKET, int);
    int (WSAAPI *getsockname)(SOCKET, struct sockaddr *, int *);
    int (WSAAPI *closesocket)(SOCKET);
    int (WSAAPI *last_error)(void);
} ws;

static int load_winsock(void) {
    if (ws.startup) return 0;
    HMODULE module = LoadLibraryW(L"ws2_32.dll");
    if (!module) return last_error();
#define GET(field, name) *(FARPROC *) &ws.field = GetProcAddress(module, name)
    GET(socket, "socket");
    GET(connect, "connect");
    GET(bind, "bind");
    GET(listen, "listen");
    GET(getsockname, "getsockname");
    GET(closesocket, "closesocket");
    GET(last_error, "WSAGetLastError");
    GET(startup, "WSAStartup");
#undef GET
    WSADATA data;
    return ws.startup && ws.startup(MAKEWORD(2, 2), &data) == 0 ? 0 : -2;
}

static unsigned short swap16(unsigned short v) { return (unsigned short) ((v << 8) | (v >> 8)); }

static int a_connect(void) {
    int loaded = load_winsock();
    if (loaded) return loaded;
    SOCKET s = ws.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return ws.last_error();
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = swap16(port);
    address.sin_addr.s_addr = 0x0100007f; /* 127.0.0.1 */
    int result = ws.connect(s, (struct sockaddr *) &address, sizeof(address)) == 0 ? 0 : ws.last_error();
    ws.closesocket(s);
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
    HMODULE user32 = LoadLibraryW(L"user32.dll");
    if (!user32) return last_error();
    typedef BOOL(WINAPI * open_fn)(HWND);
    typedef BOOL(WINAPI * plain_fn)(void);
    open_fn open_clipboard = (open_fn) (void (*)(void)) GetProcAddress(user32, "OpenClipboard");
    plain_fn empty_clipboard = (plain_fn) (void (*)(void)) GetProcAddress(user32, "EmptyClipboard");
    plain_fn close_clipboard = (plain_fn) (void (*)(void)) GetProcAddress(user32, "CloseClipboard");
    if (!open_clipboard || !empty_clipboard || !close_clipboard) return -3;
    if (!open_clipboard(NULL)) return last_error();
    int result = empty_clipboard() ? 0 : last_error();
    close_clipboard();
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
        word[0] = 0;
        r = sbx_open(path, SBX_OPEN_READ, &handle);
        if (r == 0) {
            read_word(handle, word, sizeof(word));
            CloseHandle(handle);
        }
        if (r != 0 || strcmp(word, "put") != 0) printf("info reading it back: sbx_open %d, read \"%s\"\n", r, word);
        check("which reads back", r == 0 && strcmp(word, "put") == 0);
    }
    check("SBX_OPEN_EXCLUSIVE refuses an existing file",
          sbx_open(path, SBX_OPEN_WRITE | SBX_OPEN_CREATE | SBX_OPEN_EXCLUSIVE, &handle) == -EEXIST);

    utf8_path(path, sizeof(path), L"secret\\key");
    check("sbx_open outside the rules is refused", sbx_open(path, SBX_OPEN_READ, &handle) == -EACCES);

    /* The agent's flow (Droidtop/tracker#606): its decider grants one open of a path no rule covers, then refuses. */
    utf8_path(path, sizeof(path), L"granted\\once.txt");
    r = sbx_open(path, SBX_OPEN_READ, &handle);
    check("the decider grants a path no rule covers, once", r == 0);
    if (r == 0) {
        read_word(handle, word, sizeof(word));
        CloseHandle(handle);
        check("which reads", strcmp(word, "once") == 0);
    }
    check("the second open of it is refused by the decider (-EACCES)", sbx_open(path, SBX_OPEN_READ, &handle) == -EACCES);
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

static char root8[MAX_PATH * 3], profile8[MAX_PATH * 3], exe_dir8[MAX_PATH * 3], exe8[MAX_PATH * 3], port8[16], pid8[16];
static int audit_refusals;
static void count_refusals(void *context, const struct sbx_access *access, int result) {
    (void) context;
    if (result != 0) {
        InterlockedIncrement((volatile LONG *) &audit_refusals);
        fprintf(stderr, "     audit: refused %s %s: %d\n", access->op, access->asked, result);
    }
}

/* The agent's decider, as a test: one open of granted\once.txt, then the rules' refusal again. */
static volatile LONG granted_used;
static int grant_once(void *context, const struct sbx_access *access) {
    (void) context;
    static const char leaf[] = "granted\\once.txt";
    size_t n = strlen(access->asked), m = sizeof(leaf) - 1;
    if (n >= m && _stricmp(access->asked + n - m, leaf) == 0 && InterlockedExchange(&granted_used, 1) == 0) return 0;
    return SBX_KEEP;
}

/* One confined run of the child, and its judgement against the control. */
static void confined_run(int less, const struct result *control, size_t control_count) {
    const char *label = less ? "less-privileged" : "appcontainer";
    struct result confined[64], checks[64];
    size_t confined_count = 0, check_count = 0;
    SECURITY_ATTRIBUTES inherit = {sizeof(inherit), NULL, TRUE};
    wchar_t path[MAX_PATH];
    audit_refusals = 0;
    /* Confined. */
    {
        struct sbx_policy *policy = sbx_policy_new();
        char game8[MAX_PATH * 3], save8[MAX_PATH * 3];
        utf8_path(game8, sizeof(game8), L"game");
        utf8_path(save8, sizeof(save8), L"save");
        EXPECT(sbx_policy_add(policy, game8, SBX_READ) == 0 && sbx_policy_add(policy, save8, SBX_READ | SBX_WRITE) == 0 &&
                   sbx_policy_add(policy, exe_dir8, SBX_READ | SBX_STATIC) == 0,
               "the policy");
        sbx_policy_set_audit(policy, count_refusals, NULL);
        granted_used = 0;
        sbx_policy_set_decider(policy, grant_once, NULL);
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
        spec.less_privileged = less;
        spec.memory_limit = MEMORY_LIMIT;
        spec.policy = policy;
        struct sbx_process process;
        int spawned = sbx_spawn(&spec, &process);
        CloseHandle(write_end);
        if (error_out) CloseHandle(error_out);
        printf("---- %s: sbx_spawn: %d (Windows error %lu), less-privileged: %d\n", label, spawned, sbx_spawn_error(),
               spawned == 0 ? process.less_privileged : -1);
        EXPECT(spawned == 0, "the confined child starts");
        if (spawned == 0) {
            check_count = collect(read_end, confined, &confined_count, checks, 64);
            int code = -1;
            int waited = sbx_process_wait(&process, &code);
            printf("     the confined child's exit code: 0x%08x\n", (unsigned) code);
            EXPECT(waited == 0 && code == 0, "the confined child exits cleanly");
        }
        CloseHandle(read_end);
    }

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
        snprintf(what, sizeof(what), "%s: broker: %s", label, checks[i].name);
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
    DeleteFileW(path);

}

/*
 * ---- Real Python under the backend (docs/design.md, "What is left on Windows", item 1) ----
 *
 * tests/python_win.py, passed with -c, run by the runner's own python.exe
 * (SBX_TEST_PYTHON) unconfined as the control, then under sbx_spawn in each
 * container kind. Every attempt that got through unconfined must be refused
 * confined, and everything a plugin needs must still work.
 */
#define PY_ITEMS 32
struct py_item {
    char kind[16];
    char name[48];
    char value[48];
};

/* Appends one argument quoted the way the C runtime reads a command line. */
static void quote_into(wchar_t *line, size_t size, const wchar_t *argument) {
    size_t used = wcslen(line);
    if (used && used + 1 < size) line[used++] = L' ';
    if (used + 1 < size) line[used++] = L'"';
    unsigned backslashes = 0;
    for (const wchar_t *c = argument; *c; c++) {
        if (*c == L'\\') { backslashes++; continue; }
        unsigned n = *c == L'"' ? backslashes * 2 + 1 : backslashes;
        for (unsigned k = 0; k < n && used + 1 < size; k++) line[used++] = L'\\';
        backslashes = 0;
        if (used + 1 < size) line[used++] = *c;
    }
    for (unsigned k = 0; k < backslashes * 2 && used + 1 < size; k++) line[used++] = L'\\';
    if (used + 1 < size) line[used++] = L'"';
    line[used] = 0;
}

static size_t py_collect(HANDLE pipe, struct py_item *items) {
    static char text[16384];
    DWORD used = 0, got;
    while (used + 1 < sizeof(text) && ReadFile(pipe, text + used, (DWORD) (sizeof(text) - 1 - used), &got, NULL) && got) {
        used += got;
    }
    text[used] = 0;
    size_t count = 0;
    for (char *line = strtok(text, "\r\n"); line && count < PY_ITEMS; line = strtok(NULL, "\r\n")) {
        if (sscanf(line, "%15s %47s %47s", items[count].kind, items[count].name, items[count].value) == 3) count++;
    }
    return count;
}

static const char *py_value(const struct py_item *items, size_t count, const char *kind, const char *name) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(items[i].kind, kind) == 0 && strcmp(items[i].name, name) == 0) return items[i].value;
    }
    return NULL;
}

static char python8[MAX_PATH * 3], python_dir8[MAX_PATH * 3];
static char bundle8[MAX_PATH * 3];  /* the interpreter as the agent bundles it, for the less-privileged run */
static wchar_t python_dir[MAX_PATH];

/* Runs the script; confined < 0: the control. Returns the items it reported. */
static size_t py_run(int confined, const wchar_t *script, const char *profile_file8, const char *granted8,
                     const char *marker8, struct py_item *items) {
    SECURITY_ATTRIBUTES inherit = {sizeof(inherit), NULL, TRUE};
    HANDLE read_end, write_end;
    CreatePipe(&read_end, &write_end, &inherit, 0);
    SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);
    char handle8[32], helper8[MAX_PATH * 3];
    snprintf(handle8, sizeof(handle8), "%llu", (unsigned long long) (uintptr_t) write_end);
    snprintf(helper8, sizeof(helper8), "%s\\sbx_py_helper.dll", exe_dir8);
    size_t count = 0;
    if (confined < 0) {
        static wchar_t line[24000];
        wchar_t python[MAX_PATH], argument[MAX_PATH * 2];
        MultiByteToWideChar(CP_UTF8, 0, python8, -1, python, MAX_PATH);
        line[0] = 0;
        quote_into(line, 24000, python);
        quote_into(line, 24000, L"-I");
        quote_into(line, 24000, L"-c");
        quote_into(line, 24000, script);
        const char *rest[] = {handle8, port8, pid8, profile_file8, profile8, helper8, granted8, marker8};
        for (size_t i = 0; i < 8; i++) {
            MultiByteToWideChar(CP_UTF8, 0, rest[i], -1, argument, MAX_PATH * 2);
            quote_into(line, 24000, argument);
        }
        STARTUPINFOW startup;
        memset(&startup, 0, sizeof(startup));
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION info;
        if (CreateProcessW(NULL, line, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startup, &info)) {
            CloseHandle(write_end);
            count = py_collect(read_end, items);
            WaitForSingleObject(info.hProcess, 60000);
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
        } else {
            CloseHandle(write_end);
        }
    } else {
        static char script8[24000 * 3];
        WideCharToMultiByte(CP_UTF8, 0, script, -1, script8, sizeof(script8), NULL, NULL);
        char *argv[] = {confined == 1 && bundle8[0] ? bundle8 : python8, "-I", "-c", script8, handle8, port8, pid8, (char *) profile_file8, profile8, helper8,
                        (char *) granted8, (char *) marker8, NULL};
        struct sbx_policy *policy = sbx_policy_new();
        sbx_policy_add(policy, python_dir8, SBX_READ | SBX_STATIC);  /* the interpreter and its standard library */
        sbx_policy_add(policy, exe_dir8, SBX_READ | SBX_STATIC);     /* the sbx_open helper DLL */
        sbx_policy_add(policy, granted8, SBX_READ);                  /* the one file the broker hands it */
        struct sbx_spawn_spec spec;
        memset(&spec, 0, sizeof(spec));
        spec.path = python8;
        spec.argv = argv;
        spec.handles = &write_end;
        spec.handle_count = 1;
        spec.container = CONTAINER;
        spec.less_privileged = confined;
        spec.memory_limit = 1ull << 30;
        spec.policy = policy;
        /* The interpreter's stderr, to a file the test shows when a check fails. */
        wchar_t errors_path[MAX_PATH];
        child_path(errors_path, L"python-stderr.txt");
        HANDLE errors = CreateFileW(errors_path, GENERIC_WRITE, FILE_SHARE_READ, &inherit, CREATE_ALWAYS, 0, NULL);
        spec.std_err = errors != INVALID_HANDLE_VALUE ? errors : NULL;
        struct sbx_process process;
        int started = sbx_spawn(&spec, &process);
        CloseHandle(write_end);
        if (errors != INVALID_HANDLE_VALUE) CloseHandle(errors);
        if (started == 0) {
            count = py_collect(read_end, items);
            int code = -1;
            sbx_process_wait(&process, &code);
            if (count < 13) printf("info python: the confined interpreter exited with %d\n", code);
        } else {
            printf("info python: sbx_spawn failed: %d (Windows error %lu)\n", started, sbx_spawn_error());
        }
    }
    CloseHandle(read_end);
    return count;
}

/*
 * When the interpreter dies before it reports (STATUS_ACCESS_DENIED at load),
 * which DLL the container may not load, and why: this program, confined the
 * same way, opens and loads each DLL in Python's folder and each DLL those
 * import by name. Its exit code packs two Windows errors (0: fine): opening
 * the file for read and execute, and loading it. Each DLL in Python's folder
 * also prints its security descriptor (owner, DACL, label) as SDDL.
 */
static int probe_one(const char *what, int less) {
    char *argv[] = {exe8, "--load", (char *) what, NULL};
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, exe_dir8, SBX_READ | SBX_STATIC);
    sbx_policy_add(policy, python_dir8, SBX_READ | SBX_STATIC);
    struct sbx_spawn_spec spec;
    memset(&spec, 0, sizeof(spec));
    spec.path = exe8;
    spec.argv = argv;
    spec.container = CONTAINER;
    spec.less_privileged = less;
    spec.policy = policy;
    struct sbx_process process;
    int code = -1;
    if (sbx_spawn(&spec, &process) == 0) sbx_process_wait(&process, &code);
    if (code < 0) printf("info dll probe (%s): %s -> spawn or exit %d\n", less ? "less-privileged" : "appcontainer", what, code);
    else printf("info dll probe (%s): %s -> open %d, load %d\n", less ? "less-privileged" : "appcontainer", what,
                (code >> 16) & 0xffff, code & 0xffff);
    return code;
}

static void print_sddl(const wchar_t *path, const char *name8) {
    PSECURITY_DESCRIPTOR descriptor = NULL;
    SECURITY_INFORMATION what = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    DWORD error = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, what, NULL, NULL, NULL, NULL, &descriptor);
    wchar_t *sddl = NULL;
    if (error == ERROR_SUCCESS && ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1, what, &sddl, NULL)) {
        static char sddl8[8192];
        to_utf8(sddl8, sizeof(sddl8), sddl);
        printf("info dll sddl: %s %s\n", name8, sddl8);
        LocalFree(sddl);
    } else {
        printf("info dll sddl: %s unreadable (%lu)\n", name8, error ? error : GetLastError());
    }
    if (descriptor) LocalFree(descriptor);
}

/* The DLL names path imports at load (not delay-loaded), added to names[] once each. */
static int import_names(const wchar_t *path, char names[][64], int count, int max) {
    HMODULE module = LoadLibraryExW(path, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!module) return count;
    const BYTE *base = (const BYTE *) module;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *) (base + ((const IMAGE_DOS_HEADER *) base)->e_lfanew);
    IMAGE_DATA_DIRECTORY directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory.VirtualAddress) {
        for (const IMAGE_IMPORT_DESCRIPTOR *d = (const void *) (base + directory.VirtualAddress); d->Name; d++) {
            const char *name = (const char *) (base + d->Name);
            int seen = 0;
            for (int i = 0; i < count; i++) seen |= _stricmp(names[i], name) == 0;
            if (!seen && count < max) snprintf(names[count++], 64, "%s", name);
        }
    }
    FreeLibrary(module);
    return count;
}

static void print_streams(const wchar_t *path, const char *name8) {
    WIN32_FIND_STREAM_DATA stream;
    HANDLE search = FindFirstStreamW(path, FindStreamInfoStandard, &stream, 0);
    if (search == INVALID_HANDLE_VALUE) return;
    do {
        char stream8[MAX_PATH * 3];
        to_utf8(stream8, sizeof(stream8), stream.cStreamName);
        printf("info dll stream: %s %s (%lld bytes)\n", name8, stream8, (long long) stream.StreamSize.QuadPart);
    } while (FindNextStreamW(search, &stream));
    FindClose(search);
}

static int copy_bytes(const wchar_t *from, const wchar_t *to) {
    HANDLE in = CreateFileW(from, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (in == INVALID_HANDLE_VALUE) return 0;
    HANDLE out = CreateFileW(to, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    int ok = out != INVALID_HANDLE_VALUE;
    static char buffer[65536];
    DWORD got = 0, put = 0;
    while (ok && ReadFile(in, buffer, sizeof(buffer), &got, NULL) && got) ok = WriteFile(out, buffer, got, &put, NULL) && put == got;
    CloseHandle(in);
    if (out != INVALID_HANDLE_VALUE) CloseHandle(out);
    return ok;
}

/*
 * A DLL's PE header facts that differ between images, and two edits for the
 * probe: what to print (mode 0), or the copy at path rewritten with the CET
 * shadow-stack compatibility bit cleared (mode 1) or Control Flow Guard's
 * flag cleared (mode 2). 1 when it did what was asked.
 */
static DWORD rva_to_offset(const IMAGE_NT_HEADERS *nt, DWORD rva) {
    const IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        DWORD size = section->SizeOfRawData > section->Misc.VirtualSize ? section->SizeOfRawData : section->Misc.VirtualSize;
        if (rva >= section->VirtualAddress && rva < section->VirtualAddress + size) {
            return rva - section->VirtualAddress + section->PointerToRawData;
        }
    }
    return 0;
}

static int pe_facts(const wchar_t *path, const char *name8, int mode) {
    HANDLE file = CreateFileW(path, GENERIC_READ | (mode ? GENERIC_WRITE : 0), FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    DWORD size = GetFileSize(file, NULL), got = 0;
    BYTE *image = size != INVALID_FILE_SIZE ? malloc(size) : NULL;
    int done = 0;
    if (image && ReadFile(file, image, size, &got, NULL) && got == size && size > sizeof(IMAGE_DOS_HEADER)) {
        LONG at = ((IMAGE_DOS_HEADER *) image)->e_lfanew;
        IMAGE_NT_HEADERS *nt = at > 0 && (DWORD) at + sizeof(IMAGE_NT_HEADERS) < size ? (IMAGE_NT_HEADERS *) (image + at) : NULL;
        DWORD ex = 0, *ex_at = NULL, guard = 0, tls = 0;
        if (nt) {
            IMAGE_DATA_DIRECTORY debug = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            DWORD off = debug.VirtualAddress ? rva_to_offset(nt, debug.VirtualAddress) : 0;
            for (DWORD k = 0; off && k < debug.Size / sizeof(IMAGE_DEBUG_DIRECTORY); k++) {
                IMAGE_DEBUG_DIRECTORY *d = (IMAGE_DEBUG_DIRECTORY *) (image + off) + k;
                if ((BYTE *) (d + 1) > image + size) break;
                if (d->Type == 20 /* IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS */ && d->PointerToRawData + 4 <= size) {
                    ex_at = (DWORD *) (image + d->PointerToRawData);
                    ex = *ex_at;
                }
            }
            IMAGE_DATA_DIRECTORY config = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            DWORD config_off = config.VirtualAddress ? rva_to_offset(nt, config.VirtualAddress) : 0;
            /* GuardFlags' offset in the 64-bit load configuration (older MinGW headers lack the field). */
            const DWORD guard_at = sizeof(void *) == 8 ? 0x90 : 0x58;
            if (config_off && config.Size >= guard_at + 4 && config_off + guard_at + 4 <= size) {
                memcpy(&guard, image + config_off + guard_at, sizeof(guard));
            }
            tls = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
            /* The resource directory's root: whether a side-by-side manifest (RT_MANIFEST, 24) is there. */
            IMAGE_DATA_DIRECTORY resources = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
            DWORD res_off = resources.VirtualAddress ? rva_to_offset(nt, resources.VirtualAddress) : 0;
            IMAGE_RESOURCE_DIRECTORY_ENTRY *manifest = NULL;
            if (res_off && res_off + sizeof(IMAGE_RESOURCE_DIRECTORY) <= size) {
                IMAGE_RESOURCE_DIRECTORY *root_dir = (IMAGE_RESOURCE_DIRECTORY *) (image + res_off);
                IMAGE_RESOURCE_DIRECTORY_ENTRY *e = (IMAGE_RESOURCE_DIRECTORY_ENTRY *) (root_dir + 1);
                unsigned entries = root_dir->NumberOfNamedEntries + root_dir->NumberOfIdEntries;
                for (unsigned k = 0; k < entries && (BYTE *) (e + k + 1) <= image + size; k++) {
                    if (!(e[k].Name & 0x80000000u) && e[k].Name == 24) manifest = &e[k];
                }
            }
            if (mode == 0) printf("info dll pe: %s manifest %s\n", name8, manifest ? "yes" : "no");
            if (mode == 0) {
                printf("info dll pe: %s characteristics 0x%04x ex 0x%08lx guard 0x%08lx tls %lu\n", name8,
                       (unsigned) nt->OptionalHeader.DllCharacteristics, ex, guard, tls);
                done = 1;
            } else if (mode == 1 && ex_at && (ex & 1)) {
                *ex_at = ex & ~(DWORD) 1;
                done = 1;
            } else if (mode == 3 && manifest) {
                manifest->Name = 0x7ff0;  /* a type nothing reads: the loader no longer finds a manifest */
                done = 1;
            } else if (mode == 2 && (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)) {
                nt->OptionalHeader.DllCharacteristics &= (WORD) ~IMAGE_DLLCHARACTERISTICS_GUARD_CF;
                done = 1;
            }
            DWORD put = 0;
            if (done && mode) {
                done = SetFilePointer(file, 0, NULL, FILE_BEGIN) == 0 && WriteFile(file, image, size, &put, NULL) && put == size;
            }
        }
    }
    free(image);
    CloseHandle(file);
    return done;
}

static int strip_signature(const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    static BYTE head[4096];
    DWORD got = 0, put = 0;
    int ok = ReadFile(file, head, sizeof(head), &got, NULL) && got >= sizeof(IMAGE_DOS_HEADER);
    LONG at = ok ? ((IMAGE_DOS_HEADER *) head)->e_lfanew : 0;
    ok = ok && at > 0 && (DWORD) at + sizeof(IMAGE_NT_HEADERS) <= got;
    if (ok) {
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *) (head + at);
        IMAGE_DATA_DIRECTORY *security = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        ok = security->VirtualAddress != 0;
        security->VirtualAddress = 0;
        security->Size = 0;
        nt->OptionalHeader.CheckSum = 0;
        ok = ok && SetFilePointer(file, 0, NULL, FILE_BEGIN) == 0 && WriteFile(file, head, got, &put, NULL) && put == got;
    }
    CloseHandle(file);
    return ok;
}

static void dll_probe(int less) {
    wchar_t pattern[MAX_PATH];
    swprintf(pattern, MAX_PATH, L"%ls\\*.dll", python_dir);
    WIN32_FIND_DATAW found;
    HANDLE search = FindFirstFileW(pattern, &found);
    if (search == INVALID_HANDLE_VALUE) return;
    static char imports[96][64];
    int import_count = 0;
    do {
        char dll8[MAX_PATH * 3], name8[MAX_PATH * 3];
        wchar_t dll[MAX_PATH];
        swprintf(dll, MAX_PATH, L"%ls\\%ls", python_dir, found.cFileName);
        to_utf8(dll8, sizeof(dll8), dll);
        to_utf8(name8, sizeof(name8), found.cFileName);
        print_sddl(dll, name8);
        pe_facts(dll, name8, 0);
        int code = probe_one(dll8, less);
        print_streams(dll, name8);
        /* A copy made byte by byte carries the same contents (and signature) but none of the file's
           streams or extended attributes: whether it loads says which of the two is refused. */
        if (code > 0 && (code & 0xffff)) {
            wchar_t copy[MAX_PATH];
            swprintf(copy, MAX_PATH, L"%ls\\dll-copy", exe_dir);
            CreateDirectoryW(copy, NULL);
            swprintf(copy, MAX_PATH, L"%ls\\dll-copy\\%ls", exe_dir, found.cFileName);
            if (copy_bytes(dll, copy)) {
                char copy8[MAX_PATH * 3];
                to_utf8(copy8, sizeof(copy8), copy);
                probe_one(copy8, less);
                /* The same copy with its Authenticode signature taken out: the security directory emptied. */
                if (strip_signature(copy)) {
                    printf("info dll probe: %s unsigned:\n", name8);
                    probe_one(copy8, less);
                }
                /* Then the unsigned copy without CET shadow-stack compatibility, and a fresh one without CFG's flag. */
                if (pe_facts(copy, name8, 1)) {
                    printf("info dll probe: %s unsigned, CET compatibility cleared:\n", name8);
                    probe_one(copy8, less);
                }
                if (copy_bytes(dll, copy) && strip_signature(copy) && pe_facts(copy, name8, 3)) {
                    printf("info dll probe: %s unsigned, manifest hidden:\n", name8);
                    probe_one(copy8, less);
                }
                if (copy_bytes(dll, copy) && strip_signature(copy) && pe_facts(copy, name8, 2)) {
                    printf("info dll probe: %s unsigned, CFG flag cleared:\n", name8);
                    probe_one(copy8, less);
                }
                DeleteFileW(copy);
            }
            *wcsrchr(copy, L'\\') = 0;
            RemoveDirectoryW(copy);
        }
        import_count = import_names(dll, imports, import_count, 96);
    } while (FindNextFileW(search, &found));
    FindClose(search);
    char folder8[MAX_PATH * 3];
    snprintf(folder8, sizeof(folder8), "%s", python_dir8);
    print_sddl(python_dir, folder8);
    /* Imports found beside Python are probed above; the rest come from the system's search path. */
    for (int i = 0; i < import_count; i++) {
        wchar_t beside[MAX_PATH], name[64];
        MultiByteToWideChar(CP_UTF8, 0, imports[i], -1, name, 64);
        swprintf(beside, MAX_PATH, L"%ls\\%ls", python_dir, name);
        if (GetFileAttributesW(beside) != INVALID_FILE_ATTRIBUTES) continue;
        probe_one(imports[i], less);
    }
}

/*
 * The interpreter as the agent bundles it (docs/design.md, "What is left on
 * Windows"): python.exe, its DLLs and its extension modules, with no
 * side-by-side manifest embedded in any of them. A
 * less-privileged container is refused the activation context the loader
 * builds from a DLL's manifest: python312.dll fails to load (error 5) with
 * its manifest and loads without it (CI 42063916251, x64). The standard
 * library stays where it is, named by a python._pth file, as Python's
 * embeddable distribution does. Into exe_dir\py-bundle; bundle8 names its
 * python.exe, or stays empty when it could not be made.
 */
static void copy_without_manifests(const wchar_t *from_dir, const wchar_t *to_dir, const wchar_t *pattern) {
    wchar_t search_path[MAX_PATH];
    swprintf(search_path, MAX_PATH, L"%ls\\%ls", from_dir, pattern);
    WIN32_FIND_DATAW found;
    HANDLE search = FindFirstFileW(search_path, &found);
    if (search == INVALID_HANDLE_VALUE) return;
    do {
        wchar_t from[MAX_PATH], to[MAX_PATH];
        swprintf(from, MAX_PATH, L"%ls\\%ls", from_dir, found.cFileName);
        swprintf(to, MAX_PATH, L"%ls\\%ls", to_dir, found.cFileName);
        if (!copy_bytes(from, to)) continue;
        strip_signature(to);
        char name8[MAX_PATH * 3];
        to_utf8(name8, sizeof(name8), found.cFileName);
        pe_facts(to, name8, 3);
    } while (FindNextFileW(search, &found));
    FindClose(search);
}

static void make_bundle(void) {
    bundle8[0] = 0;
    wchar_t bundle[MAX_PATH], dlls[MAX_PATH], from_dlls[MAX_PATH], exe_from[MAX_PATH], exe_to[MAX_PATH], pth[MAX_PATH];
    swprintf(bundle, MAX_PATH, L"%ls\\py-bundle", exe_dir);
    swprintf(dlls, MAX_PATH, L"%ls\\DLLs", bundle);
    swprintf(from_dlls, MAX_PATH, L"%ls\\DLLs", python_dir);
    CreateDirectoryW(bundle, NULL);
    CreateDirectoryW(dlls, NULL);
    swprintf(exe_from, MAX_PATH, L"%ls\\python.exe", python_dir);
    swprintf(exe_to, MAX_PATH, L"%ls\\python.exe", bundle);
    if (!copy_bytes(exe_from, exe_to)) return;
    /* The executable's own manifest too: with every DLL clean, the bundled python.exe still died at load (CI 42082633096). */
    strip_signature(exe_to);
    pe_facts(exe_to, "python.exe", 3);
    copy_without_manifests(python_dir, bundle, L"*.dll");
    copy_without_manifests(from_dlls, dlls, L"*.pyd");
    copy_without_manifests(from_dlls, dlls, L"*.dll");
    /* The library path: the original standard library, then the bundle's own extension modules. */
    swprintf(pth, MAX_PATH, L"%ls\\python._pth", bundle);  /* named for the executable, as Python accepts */
    char lines[MAX_PATH * 3 + 64];
    snprintf(lines, sizeof(lines), "%s\\Lib\r\nDLLs\r\n.\r\n", python_dir8);
    make_file(pth, lines);
    to_utf8(bundle8, sizeof(bundle8), exe_to);
}

/* Spawns program with argv under the probe's grants; its exit code (or -1 when it did not start). */
static int spawn_exit(const char *program, char **argv, int less) {
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, exe_dir8, SBX_READ | SBX_STATIC);
    sbx_policy_add(policy, python_dir8, SBX_READ | SBX_STATIC);
    struct sbx_spawn_spec spec;
    memset(&spec, 0, sizeof(spec));
    spec.path = program;
    spec.argv = argv;
    spec.container = CONTAINER;
    spec.less_privileged = less;
    spec.policy = policy;
    struct sbx_process process;
    int code = -1;
    if (sbx_spawn(&spec, &process) == 0) sbx_process_wait(&process, &code);
    else printf("info bundle probe: sbx_spawn of %s failed (Windows error %lu)\n", program, sbx_spawn_error());
    return code;
}

static void bundle_probe(int less) {
    /* 1. python.exe itself as a module: its whole import closure, resolved from the bundle. */
    probe_one(bundle8, less);
    /* 2. The bundled interpreter with nothing but -I -c pass: no channel, no script. */
    char *plain[] = {bundle8, "-I", "-c", "pass", NULL};
    printf("info bundle probe: bundled python.exe -I -c pass -> %d\n", spawn_exit(bundle8, plain, less));
    /* 3. This test program, copied into the bundle's folder, loading kernel32: whether the folder itself matters. */
    wchar_t from[MAX_PATH], to[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, exe8, -1, from, MAX_PATH);
    MultiByteToWideChar(CP_UTF8, 0, bundle8, -1, to, MAX_PATH);
    wcscpy(wcsrchr(to, L'\\') + 1, L"sbx_test_copy.exe");
    if (copy_bytes(from, to)) {
        char to8[MAX_PATH * 3];
        to_utf8(to8, sizeof(to8), to);
        char *load[] = {to8, "--load", "kernel32.dll", NULL};
        printf("info bundle probe: this program from the bundle's folder -> %d\n", spawn_exit(to8, load, less));
        DeleteFileW(to);
    }
    /* 4. The original python.exe with -I -c pass, for comparison. */
    char *original[] = {python8, "-I", "-c", "pass", NULL};
    printf("info bundle probe: original python.exe -I -c pass -> %d\n", spawn_exit(python8, original, less));
}

static void python_checks(void) {
    wchar_t python[MAX_PATH];
    if (!GetEnvironmentVariableW(L"SBX_TEST_PYTHON", python, MAX_PATH)) {
        printf("skip python: SBX_TEST_PYTHON names no python.exe here\n");
        return;
    }
    to_utf8(python8, sizeof(python8), python);
    wcscpy(python_dir, python);
    *wcsrchr(python_dir, L'\\') = 0;
    to_utf8(python_dir8, sizeof(python_dir8), python_dir);
    make_bundle();
    printf("info python: the bundled interpreter for the less-privileged run: %s\n", bundle8[0] ? bundle8 : "(not made)");
    /* The script, read from the source tree. */
    static wchar_t script[24000];
    FILE *f = fopen(SBX_TEST_SOURCE_DIR "/tests/python_win.py", "rb");
    static char raw[24000];
    size_t n = f ? fread(raw, 1, sizeof(raw) - 1, f) : 0;
    if (f) fclose(f);
    raw[n] = 0;
    MultiByteToWideChar(CP_UTF8, 0, raw, -1, script, 24000);
    EXPECT(n > 0, "python: the plugin script");
    /* A file in the profile, and the one file the broker grants. */
    wchar_t profile_file[MAX_PATH], path[MAX_PATH];
    swprintf(profile_file, MAX_PATH, L"%ls\\sbx-test-python-%lu.txt", profile, GetCurrentProcessId());
    make_file(profile_file, "profile");
    child_path(path, L"plugin-data");
    CreateDirectoryW(path, NULL);
    child_path(path, L"plugin-data\\granted.txt");
    make_file(path, "granted");
    char profile_file8[MAX_PATH * 3], granted8[MAX_PATH * 3];
    to_utf8(profile_file8, sizeof(profile_file8), profile_file);
    to_utf8(granted8, sizeof(granted8), path);

    /*
     * os.startfile is judged by its effect alone (the marker, above): in a
     * less-privileged container ShellExecute can report success and start
     * nothing (seen on ARM64, CI 41970274514), which is a refusal all the same.
     */
    static const char *const must_refuse[] = {"subprocess", "ctypes-createprocess", "socket-loopback",
                                              "socket-public", "ctypes-registry", "ctypes-openprocess",
                                              "open-profile-file", "list-profile"};
    /*
     * In a less-privileged container Python's _socket cannot start Winsock,
     * so socket, and ssl which imports it, fail at import (CI 41970274514,
     * ARM64): the network is refused before any call. So ssl must import in
     * the plain container only.
     */
    static const char *const must_work[] = {"import-json", "import-ssl", "import-ctypes", "sbx-open"};
    /* Where a program the script launched would leave its mark: the parent's temporary folder. */
    wchar_t marker[MAX_PATH], temp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_dir);
    swprintf(marker, MAX_PATH, L"%lssbx-test-launched-%lu.txt", temp_dir, GetCurrentProcessId());
    char marker8[MAX_PATH * 3];
    to_utf8(marker8, sizeof(marker8), marker);
    struct py_item control[PY_ITEMS];
    size_t control_count = py_run(-1, script, profile_file8, granted8, marker8, control);
    Sleep(2000);
    EXPECT(GetFileAttributesW(marker) != INVALID_FILE_ATTRIBUTES, "python control: a launched program leaves its marker");
    DeleteFileW(marker);
    EXPECT(control_count >= 13, "python control: the script ran unconfined and reported");
    for (int less = 0; less <= 1; less++) {
        const char *label = less ? "python, less-privileged" : "python, appcontainer";
        struct py_item confined[PY_ITEMS];
        size_t confined_count = py_run(less, script, profile_file8, granted8, marker8, confined);
        char what[160];
        /* A launch that reports success but hands the program to someone outside the job would leave the marker. */
        Sleep(2000);
        snprintf(what, sizeof(what), "%s: no program it asked for ran, inside the job or out (no marker)", label);
        EXPECT(GetFileAttributesW(marker) == INVALID_FILE_ATTRIBUTES, what);
        DeleteFileW(marker);
        snprintf(what, sizeof(what), "%s: the confined interpreter ran the plugin and reported", label);
        EXPECT(confined_count >= 13, what);
        for (size_t i = 0; i < sizeof(must_refuse) / sizeof(must_refuse[0]); i++) {
            const char *before = py_value(control, control_count, "attempt", must_refuse[i]);
            const char *after = py_value(confined, confined_count, "attempt", must_refuse[i]);
            if (!before || strcmp(before, "0") != 0) {
                printf("info %s: %s did not get through unconfined either (%s); confined: %s\n", label, must_refuse[i],
                       before ? before : "no report", after ? after : "no report");
            }
            snprintf(what, sizeof(what), "%s: %s refused (%s)", label, must_refuse[i], after ? after : "no report");
            EXPECT(after && strcmp(after, "0") != 0, what);
        }
        int all_worked = confined_count >= 13;
        for (size_t i = 0; i < sizeof(must_work) / sizeof(must_work[0]); i++) {
            if (less && strcmp(must_work[i], "import-ssl") == 0) {
                const char *ssl = py_value(confined, confined_count, "works", must_work[i]);
                printf("info %s: import-ssl %s (Winsock cannot start in a less-privileged container)\n", label,
                       ssl && strcmp(ssl, "1") == 0 ? "works" : "fails");
                continue;
            }
            const char *value = py_value(confined, confined_count, "works", must_work[i]);
            snprintf(what, sizeof(what), "%s: %s works", label, must_work[i]);
            EXPECT(value && strcmp(value, "1") == 0, what);
            if (!value || strcmp(value, "1") != 0) all_worked = 0;
        }
        if (!all_worked) {
            /* What the interpreter said on stderr, for the failing run. */
            wchar_t errors_path[MAX_PATH];
            child_path(errors_path, L"python-stderr.txt");
            FILE *errors = _wfopen(errors_path, L"rb");
            static char said[3000];
            size_t said_length = errors ? fread(said, 1, sizeof(said) - 1, errors) : 0;
            if (errors) fclose(errors);
            said[said_length] = 0;
            printf("info %s: its stderr:\n%s\n", label, said_length ? said : "(nothing)");
            if (confined_count < 13) {
                dll_probe(less);
                if (less && bundle8[0]) {
                    /* And the bundle the less-privileged run used: its own DLLs, as copied. */
                    wchar_t saved[MAX_PATH];
                    wcscpy(saved, python_dir);
                    MultiByteToWideChar(CP_UTF8, 0, bundle8, -1, python_dir, MAX_PATH);
                    *wcsrchr(python_dir, L'\\') = 0;
                    printf("info dll probe: the bundle's own files:\n");
                    dll_probe(less);
                    bundle_probe(less);
                    wcscpy(python_dir, saved);
                }
            }
        }
    }
    DeleteFileW(profile_file);
    child_path(path, L"python-stderr.txt");
    DeleteFileW(path);
    child_path(path, L"plugin-data\\granted.txt");
    DeleteFileW(path);
    child_path(path, L"plugin-data");
    RemoveDirectoryW(path);
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\sbx-test-python");
}

/* Whether path's own access list has an entry naming the container's SID (an SBX_STATIC grant left behind). */
static int has_entry_for(const wchar_t *path, const char *container) {
    wchar_t name[80];
    MultiByteToWideChar(CP_UTF8, 0, container, -1, name, 80);
    PSID sid = NULL;
    if (FAILED(DeriveAppContainerSidFromAppContainerName(name, &sid))) return 0;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    int found = 0;
    if (GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &descriptor) ==
            ERROR_SUCCESS && dacl) {
        for (DWORD i = 0; i < dacl->AceCount; i++) {
            ACCESS_ALLOWED_ACE *ace = NULL;
            if (GetAce(dacl, i, (void **) &ace) && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
                !(ace->Header.AceFlags & INHERITED_ACE) && EqualSid((PSID) &ace->SidStart, sid)) {
                found = 1;
            }
        }
    }
    if (descriptor) LocalFree(descriptor);
    FreeSid(sid);
    return found;
}

/*
 * What is left on Windows (docs/design.md; Droidtop/tracker#606): asking first,
 * a CPU cap, and removing a container with what it left.
 */
static void left_on_windows_checks(void) {
    struct sbx_probe probe;
    int can = sbx_spawn_probe(&probe);
    printf("info probe: appcontainer %d, less-privileged %d, nested jobs %d, profile %d, reason '%s'\n",
           probe.appcontainer, probe.less_privileged, probe.nested_jobs, probe.profile, probe.reason);
    EXPECT(can == 0 && probe.appcontainer && probe.nested_jobs && probe.profile && !probe.reason[0],
           "probe: this system can confine, and says so before anything starts");
    EXPECT(sbx_spawn_probe(NULL) == -EINVAL, "probe: a missing report is refused");

    /* A CPU cap: out of range refused; in range, the job carries it. */
    char *argv_idle[] = {exe8, "--idle", NULL};
    struct sbx_spawn_spec spec;
    memset(&spec, 0, sizeof(spec));
    spec.path = exe8;
    spec.argv = argv_idle;
    spec.container = CONTAINER;
    spec.cpu_percent = 101;
    struct sbx_process process;
    struct sbx_policy *refused_policy = sbx_policy_new();
    spec.policy = refused_policy;
    EXPECT(sbx_spawn(&spec, &process) == -EINVAL, "cpu cap: over 100 percent is refused, nothing started");
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, exe_dir8, SBX_READ | SBX_STATIC);
    spec.policy = policy;
    spec.cpu_percent = 10;
    int started = sbx_spawn(&spec, &process);
    EXPECT(started == 0, "cpu cap: a program starts under a 10 percent cap");
    if (started == 0) {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION rate;
        memset(&rate, 0, sizeof(rate));
        DWORD got = 0;
        int queried = QueryInformationJobObject(process.job, JobObjectCpuRateControlInformation, &rate, sizeof(rate), &got);
        EXPECT(queried && (rate.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP) && rate.CpuRate == 1000,
               "cpu cap: the job carries the hard cap (10 percent)");
        int code = -1;
        sbx_process_wait(&process, &code);
    }

    /* Removing the container: its static grant on the program's folder goes, and its profile with it. */
    EXPECT(has_entry_for(exe_dir, CONTAINER), "remove: the container's static grant is on the program's folder");
    const char *granted[] = {exe_dir8, "C:\\sbx-test-gone\\nowhere", python_dir8};
    unsigned granted_count = python_dir8[0] ? 3 : 2;
    EXPECT(sbx_container_remove(CONTAINER, granted, granted_count) == 0, "remove: the container and its grants are removed");
    EXPECT(!has_entry_for(exe_dir, CONTAINER), "remove: no entry for its SID is left on the folder");
    if (python_dir8[0]) {
        EXPECT(!has_entry_for(python_dir, CONTAINER), "remove: nor on Python's folder");
        /* Nor on a file under it whose access list is protected, which got an entry of its own (grant_static). */
        wchar_t pattern[MAX_PATH], dll[MAX_PATH];
        swprintf(pattern, MAX_PATH, L"%ls\\python3*.dll", python_dir);
        WIN32_FIND_DATAW found;
        HANDLE search = FindFirstFileW(pattern, &found);
        int left = 0;
        if (search != INVALID_HANDLE_VALUE) {
            do {
                swprintf(dll, MAX_PATH, L"%ls\\%ls", python_dir, found.cFileName);
                left |= has_entry_for(dll, CONTAINER);
            } while (FindNextFileW(search, &found));
            FindClose(search);
        }
        EXPECT(!left, "remove: nor on Python's own DLLs");
    }
    EXPECT(sbx_container_remove(CONTAINER, granted, granted_count) == 0, "remove: removing again is harmless");
    EXPECT(sbx_container_remove("", granted, 1) == -EINVAL, "remove: a container needs a name");
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--idle") == 0) return 0;
    if (argc >= 3 && strcmp(argv[1], "--load") == 0) {
        wchar_t dll[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, dll, MAX_PATH);
        /* A bare name is found the way the loader would find an import; a path is opened first. */
        DWORD open_error = 0;
        if (wcschr(dll, L'\\')) {
            HANDLE file = CreateFileW(dll, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
                                      OPEN_EXISTING, 0, NULL);
            if (file == INVALID_HANDLE_VALUE) open_error = GetLastError();
            else CloseHandle(file);
        }
        HMODULE module = LoadLibraryExW(dll, NULL, wcschr(dll, L'\\') ? LOAD_WITH_ALTERED_SEARCH_PATH : 0);
        DWORD load_error = module ? 0 : GetLastError();
        return (int) ((open_error > 0x7fff ? 0x7fff : open_error) << 16 | (load_error > 0xffff ? 0xffff : load_error));
    }
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
    child_path(path, L"granted");
    CreateDirectoryW(path, NULL);
    child_path(path, L"granted\\once.txt");
    make_file(path, "once");
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
    SOCKET listener = load_winsock() == 0 ? ws.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) : INVALID_SOCKET;
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = 0x0100007f; /* 127.0.0.1 */
    int length = sizeof(address);
    EXPECT(listener != INVALID_SOCKET && ws.bind(listener, (struct sockaddr *) &address, sizeof(address)) == 0 &&
               ws.listen(listener, 8) == 0 && ws.getsockname(listener, (struct sockaddr *) &address, &length) == 0,
           "a listening port for the network attempt");
    port = swap16(address.sin_port);
    wchar_t event_name[64];
    swprintf(event_name, 64, L"Local\\sbx-test-%lu", GetCurrentProcessId());
    HANDLE event = CreateEventW(NULL, FALSE, FALSE, event_name);
    EXPECT(event != NULL, "a named event for the named-object attempt");

    to_utf8(root8, sizeof(root8), root);
    to_utf8(profile8, sizeof(profile8), profile);
    to_utf8(exe_dir8, sizeof(exe_dir8), exe_dir);
    to_utf8(exe8, sizeof(exe8), exe_path);
    snprintf(port8, sizeof(port8), "%u", port);
    snprintf(pid8, sizeof(pid8), "%lu", GetCurrentProcessId());

    struct result control[64], unused[64];
    size_t control_count = 0;
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

    /* Confined: an AppContainer, then a less-privileged one where the system has it. */
    confined_run(0, control, control_count);
    confined_run(1, control, control_count);

    python_checks();
    left_on_windows_checks();

    /* Removes what it made, one by one (the junction itself, not what it leads to). */
    static const wchar_t *const files[] = {L"save\\new.txt", L"game\\data.txt", L"secret\\key", L"granted\\once.txt"};
    static const wchar_t *const folders[] = {L"save\\link", L"save", L"game", L"secret", L"granted"};
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
    if (listener != INVALID_SOCKET) ws.closesocket(listener);
    printf(failures ? "%d failure(s)\n" : "all passed\n", failures);
    return failures ? 1 : 0;
}
