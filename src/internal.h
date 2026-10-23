/*
 * Between the library's own files, not part of its interface.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#ifndef SBX_INTERNAL_H
#define SBX_INTERNAL_H

/*
 * The prctl option an SBX_LOCK_EXEC filter answers with ENOTRECOVERABLE
 * ("SBXE"); the kernel itself answers EINVAL. sbx_adopt asks it to know the
 * filter is in place before it calls the process confined.
 */
#define SBX_EXEC_PROBE 0x53425845

/*
 * Takes over an SBX_LOCK_EXEC lockdown in an image sbx-exec started: the
 * filter is the one the exec kept, and broker_fd, cwd_fd and helper_fd are
 * the descriptors sbx-exec and the handler passed on. Installs the full
 * handler. Fails, leaving nothing confined claimed, when the probe does not
 * answer or the trampoline page is not in place.
 */
int sbx_adopt(unsigned flags, int broker_fd, int cwd_fd, int helper_fd, const char *child_library);

#endif
