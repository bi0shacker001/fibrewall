/*
 * A consumer's program: links the library and asks it whether this system
 * can confine (sbx_spawn_probe). Exit 0 when it links and answers.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#include <stdio.h>

#include "sbx.h"

int main(void) {
    struct sbx_probe probe;
    int can = sbx_spawn_probe(&probe);
    printf("consumer: sbx %s, can confine: %s%s%s\n", SBX_VERSION, can == 0 ? "yes" : "no", probe.reason[0] ? ", " : "",
           probe.reason);
    return 0;
}
