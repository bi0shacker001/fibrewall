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

/* Nonzero makes sbx_trace_fault skip the unwind and walk frame records alone (for its test). */
extern int sbx_trace_fault_frame_pointers_only;

/*
 * A canonical byte image of a policy's rules, aliases, net grants, system
 * sockets and abstract Unix names, in their stored order. The contract's
 * report hashes it (with the lockdown flags and options) into
 * policy_digest. Returns a malloc'd buffer the caller frees and sets *len,
 * or NULL on allocation failure. The format is private and may change
 * between versions; the backend_version in the report pins it.
 */
unsigned char *sbx_policy_serialize(const struct sbx_policy *policy, size_t *len);

#endif
