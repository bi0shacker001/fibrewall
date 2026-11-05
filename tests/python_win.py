# A plugin as the agent would run it, for sbx_test_win.exe (docs/design.md,
# "What is left on Windows", item 1; Droidtop/tracker#606). The test runs it
# twice: unconfined, as the control, then under sbx_spawn. It reports on its
# channel handle, one line per attempt and per thing that must work:
#   attempt <name> <0 | the error>     0: the attempt got through
#   works <name> <1 | 0>               1: it worked
# The owner's rule: "ctypes, raw sockets and subprocess must all end at a
# refusal from the kernel".
#
# argv: channel handle, port, parent pid, a file in the profile, the profile,
#       the sbx_open helper DLL, a file the broker grants, and a marker path a
#       launched program would create (the parent checks whether one ran).
#
# Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
import os
import sys

channel_handle, port, parent_pid, profile_file, profile_dir, helper_dll, granted, marker = sys.argv[1:9]
port = int(port)
parent_pid = int(parent_pid)

import msvcrt

channel = os.fdopen(msvcrt.open_osfhandle(int(channel_handle), os.O_WRONLY), "w")


def report(line):
    channel.write(line + "\n")
    channel.flush()


def attempt(name, action):
    try:
        action()
        report("attempt %s 0" % name)
    except BaseException as error:  # a refusal, whatever form it takes
        report("attempt %s %s" % (name, type(error).__name__))


def works(name, action):
    try:
        ok = action()
        report("works %s %d" % (name, 1 if ok is not False else 0))
    except BaseException:
        import traceback

        traceback.print_exc()  # to stderr, which the test shows when a check fails
        report("works %s 0" % name)


# What must work: the standard library, ctypes itself, the channel, sbx_open.
works("import-json", lambda: __import__("json").dumps({"a": 1}) == '{"a": 1}')
works("import-ssl", lambda: __import__("ssl").OPENSSL_VERSION is not None)
works("import-ctypes", lambda: __import__("ctypes").sizeof(__import__("ctypes").c_void_p) in (4, 8))


def through_broker():
    import ctypes

    helper = ctypes.CDLL(helper_dll)
    helper.sbx_py_open.restype = ctypes.c_longlong
    helper.sbx_py_open.argtypes = [ctypes.c_char_p]
    handle = helper.sbx_py_open(granted.encode("utf-8"))
    if handle < 0:
        return False
    fd = msvcrt.open_osfhandle(handle, os.O_RDONLY)
    with os.fdopen(fd, "rb") as f:
        return f.read() == b"granted"


works("sbx-open", through_broker)


# What must be refused.
def run_subprocess():
    import subprocess

    # The interpreter itself, writing the marker: no shell quoting between the test and the effect.
    subprocess.run([sys.executable, "-I", "-c", "open(%r, 'w').write('started')" % marker], check=True, timeout=20)


def create_process():
    import ctypes
    from ctypes import wintypes

    class StartupInfo(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD)] + [("pad%d" % i, ctypes.c_void_p) for i in range(12)]

    class ProcessInfo(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("pid", wintypes.DWORD),
                    ("tid", wintypes.DWORD)]

    startup = StartupInfo()
    startup.cb = ctypes.sizeof(StartupInfo)
    info = ProcessInfo()
    command = ctypes.create_unicode_buffer("cmd.exe /c exit 0")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not kernel32.CreateProcessW(None, command, None, None, False, 0, None, None, ctypes.byref(startup),
                                   ctypes.byref(info)):
        raise OSError(ctypes.get_last_error(), "CreateProcessW")
    kernel32.WaitForSingleObject(info.hProcess, 20000)


def start_file():
    # Whether a program really started is the parent's to see: this one would leave the marker.
    os.startfile("cmd.exe", "open", '/c echo started> "%s"' % marker)


def connect(host, the_port):
    def action():
        import socket

        with socket.create_connection((host, the_port), timeout=10):
            pass

    return action


def registry():
    import winreg

    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\sbx-test-python")
    winreg.CloseKey(key)


def open_parent():
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_VM_READ = 0x10
    handle = kernel32.OpenProcess(PROCESS_VM_READ, False, parent_pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess")
    kernel32.CloseHandle(handle)


def read_profile_file():
    with open(profile_file, "rb") as f:
        f.read()


def list_profile():
    os.listdir(profile_dir)


attempt("subprocess", run_subprocess)
attempt("startfile", start_file)
attempt("ctypes-createprocess", create_process)
attempt("socket-loopback", connect("127.0.0.1", port))
attempt("socket-public", connect("1.1.1.1", 443))
attempt("ctypes-registry", registry)
attempt("ctypes-openprocess", open_parent)
attempt("open-profile-file", read_profile_file)
attempt("list-profile", list_profile)
report("done")
channel.close()
