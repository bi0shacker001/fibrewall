/*
 * libsbx_child.so: put on LD_PRELOAD by a host, it confines each process
 * of the tree before main (sbx_attach_from_environment, from SBX_BROKER,
 * SBX_TOKEN, SBX_FLAGS and SBX_OWN_OPENS). A process whose environment
 * names a broker it cannot attach to ends here, before any of its own
 * code runs: it never runs unconfined by mistake. Without SBX_BROKER it
 * does nothing. It loads beside a host's other preloads (droidtop's
 * exec and path redirects): it needs none of them and changes none.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#include "sbx.h"

#include <string.h>
#include <unistd.h>

__attribute__((constructor)) static void sbx_child_attach(void) {
    int result = sbx_attach_from_environment();
    if (result < 0) {
        static const char message[] = "sbx: could not attach to the broker; the process ends before main\n";
        ssize_t ignored = write(2, message, sizeof(message) - 1);
        (void) ignored;
        _exit(127);
    }
}
