/*
 * The python_win.py test's stand-in for the agent's droidtop.host module
 * (Droidtop/tracker#606): sbx_open, callable from Python through ctypes.
 * Returns the handle, or a negative errno.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#include <stdint.h>

#include "sbx.h"

__declspec(dllexport) long long sbx_py_open(const char *path) {
    sbx_handle handle = 0;
    int result = sbx_open(path, SBX_OPEN_READ, &handle);
    return result < 0 ? result : (long long) (intptr_t) handle;
}
