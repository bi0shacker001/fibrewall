/*
 * sbx_open's flags: which combinations are valid. One copy, used by the
 * Linux call (open.c), the Windows client (windows_client.c) and the
 * Windows broker (windows.c), so the three can never disagree (#767).
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#ifndef SBX_OPEN_FLAGS_H
#define SBX_OPEN_FLAGS_H

#include "sbx.h"

/* The flags that ask to change the file, and every flag there is. */
#define SBX_OPEN_WRITING (SBX_OPEN_WRITE | SBX_OPEN_CREATE | SBX_OPEN_TRUNCATE | SBX_OPEN_EXCLUSIVE | SBX_OPEN_APPEND)
#define SBX_OPEN_ALL (SBX_OPEN_READ | SBX_OPEN_WRITING | SBX_OPEN_DIRECTORY)

/*
 * 1 when flags make sense: only known flags; a folder is opened to list and
 * nothing else; otherwise read, write or both, truncate and append only
 * with write, exclusive only with create.
 */
static int sbx_open_flags_valid(unsigned flags) {
    if (flags & ~SBX_OPEN_ALL) return 0;
    if (flags & SBX_OPEN_DIRECTORY) return !(flags & SBX_OPEN_WRITING);
    if (!(flags & (SBX_OPEN_READ | SBX_OPEN_WRITE))) return 0;
    if ((flags & (SBX_OPEN_TRUNCATE | SBX_OPEN_APPEND)) && !(flags & SBX_OPEN_WRITE)) return 0;
    if ((flags & SBX_OPEN_EXCLUSIVE) && !(flags & SBX_OPEN_CREATE)) return 0;
    return 1;
}

#endif
