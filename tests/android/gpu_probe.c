/*
 * The native-kind feasibility probe (Android only).
 *
 * The question it answers: can a process that runs no ART, and is locked
 * down so it can open nothing by itself, still draw with the GPU into a
 * buffer its parent allocated? And does anything in the graphics stack
 * (libEGL, the vendor driver, the gralloc mapper) open binder on its own,
 * which would leave a hole a seccomp filter cannot close?
 *
 * The parent allocates an AHardwareBuffer, starts a broker whose rules
 * allow the system's read-only code, the GPU device nodes and nothing
 * else (no /dev/binder, /dev/hwbinder or /dev/vndbinder), and re-executes
 * itself as the child. The child:
 *   1. lists its binder descriptors (none expected);
 *   2. brings up EGL with a pbuffer context, then lists them again;
 *   3. locks down;
 *   4. receives the buffer over the socket, imports it as an EGLImage and
 *      draws 300 frames into it, timing them, the last one green;
 *   5. lists its binder descriptors a last time.
 * The parent then reads the buffer's centre pixel with the CPU. Every
 * refusal the broker makes is printed, so a driver's lazy open that the
 * rules missed shows up by name.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#define EGL_EGLEXT_PROTOTYPES
#define GL_GLEXT_PROTOTYPES
#include "sbx.h"

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <android/hardware_buffer.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WIDTH 256
#define HEIGHT 256
#define FRAMES 300

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

/* Prints every descriptor of this process that names a binder device; returns how many. */
static int binder_fds(const char *when) {
    DIR *fds = opendir("/proc/self/fd");
    if (!fds) {
        printf("child: %s: cannot list /proc/self/fd (%s)\n", when, strerror(errno));
        return -1;
    }
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(fds))) {
        if (entry->d_name[0] == '.') continue;
        char link[64], target[256];
        snprintf(link, sizeof(link), "/proc/self/fd/%s", entry->d_name);
        ssize_t n = readlink(link, target, sizeof(target) - 1);
        if (n <= 0) continue;
        target[n] = '\0';
        if (strstr(target, "binder")) {
            printf("child: %s: fd %s -> %s\n", when, entry->d_name, target);
            count++;
        }
    }
    closedir(fds);
    printf("child: %s: %d binder descriptor(s)\n", when, count);
    return count;
}

static int child(int broker, int control) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    binder_fds("before EGL");

    double t0 = now_ms();
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major = 0, minor = 0;
    if (display == EGL_NO_DISPLAY || !eglInitialize(display, &major, &minor)) {
        printf("child: FAIL eglInitialize (0x%x)\n", eglGetError());
        return 1;
    }
    const EGLint config_attributes[] = {EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT, EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
                                        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8,
                                        EGL_NONE};
    EGLConfig config;
    EGLint configs = 0;
    if (!eglChooseConfig(display, config_attributes, &config, 1, &configs) || configs < 1) {
        printf("child: FAIL eglChooseConfig (0x%x)\n", eglGetError());
        return 1;
    }
    const EGLint context_attributes[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attributes);
    const EGLint surface_attributes[] = {EGL_WIDTH, 16, EGL_HEIGHT, 16, EGL_NONE};
    EGLSurface surface = eglCreatePbufferSurface(display, config, surface_attributes);
    if (context == EGL_NO_CONTEXT || surface == EGL_NO_SURFACE || !eglMakeCurrent(display, surface, surface, context)) {
        printf("child: FAIL context or pbuffer (0x%x)\n", eglGetError());
        return 1;
    }
    printf("child: EGL %d.%d up in %.1f ms; GL_RENDERER %s\n", major, minor, now_ms() - t0,
           (const char *) glGetString(GL_RENDERER));
    int before = binder_fds("after EGL, before lockdown");

    int locked = sbx_lockdown(broker, SBX_LOCK_LOG_SOCKET);
    if (locked != 0) {
        printf("child: FAIL lockdown: %s\n", strerror(-locked));
        return 1;
    }
    printf("child: locked down\n");

    AHardwareBuffer *buffer = NULL;
    int received = AHardwareBuffer_recvHandleFromUnixSocket(control, &buffer);
    if (received != 0 || !buffer) {
        printf("child: FAIL receiving the buffer after lockdown: %d\n", received);
        return 1;
    }
    EGLClientBuffer client = eglGetNativeClientBufferANDROID(buffer);
    const EGLint image_attributes[] = {EGL_IMAGE_PRESERVED_KHR, EGL_TRUE, EGL_NONE};
    EGLImageKHR image = client ? eglCreateImageKHR(display, EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_ANDROID, client,
                                                   image_attributes)
                               : EGL_NO_IMAGE_KHR;
    if (image == EGL_NO_IMAGE_KHR) {
        printf("child: FAIL importing the buffer as an EGLImage (0x%x)\n", eglGetError());
        return 1;
    }
    GLuint texture, framebuffer;
    glGenTextures(1, &texture);
    glBindTexture(GL_TEXTURE_2D, texture);
    glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, (GLeglImageOES) image);
    glGenFramebuffers(1, &framebuffer);
    glBindFramebuffer(GL_FRAMEBUFFER, framebuffer);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, texture, 0);
    GLenum status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
    if (status != GL_FRAMEBUFFER_COMPLETE) {
        printf("child: FAIL framebuffer on the imported buffer: 0x%x\n", status);
        return 1;
    }
    glViewport(0, 0, WIDTH, HEIGHT);
    double start = now_ms(), worst = 0;
    for (int i = 0; i < FRAMES; i++) {
        double frame = now_ms();
        if (i == FRAMES - 1) glClearColor(0.0f, 1.0f, 0.0f, 1.0f);
        else glClearColor((i % 7) / 7.0f, 0.2f, (i % 3) / 3.0f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        glFinish();
        double took = now_ms() - frame;
        if (took > worst) worst = took;
    }
    printf("child: %d frames into the parent's buffer, %.3f ms each on average, worst %.3f ms\n", FRAMES,
           (now_ms() - start) / FRAMES, worst);
    int after = binder_fds("after lockdown and drawing");
    printf("child: binder descriptors: %d after EGL, %d at the end\n", before, after);
    char done = 'd';
    if (write(control, &done, 1) != 1) return 1;
    return 0;
}

static int refusals;

static void audit(void *context, const struct sbx_access *access, int result) {
    (void) context;
    if (result >= 0) return;
    refusals++;
    printf("broker: refused %s %s (%s): %s\n", access->op, access->asked,
           access->resolved[0] ? access->resolved : "unresolved", strerror(-result));
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc == 4 && strcmp(argv[1], "--child") == 0) return child(atoi(argv[2]), atoi(argv[3]));

    AHardwareBuffer_Desc description = {
        .width = WIDTH, .height = HEIGHT, .layers = 1, .format = AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
        .usage = AHARDWAREBUFFER_USAGE_GPU_COLOR_OUTPUT | AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                 AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN,
    };
    AHardwareBuffer *buffer = NULL;
    if (AHardwareBuffer_allocate(&description, &buffer) != 0) {
        printf("parent: FAIL AHardwareBuffer_allocate\n");
        return 1;
    }

    int broker[2], control[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, broker) != 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, control) != 0) {
        perror("socketpair");
        return 1;
    }
    struct sbx_policy *policy = sbx_policy_new();
    static const char *read_only[] = {"/system", "/vendor", "/odm", "/product", "/system_ext", "/apex",
                                      "/dev/__properties__", "/sys", "/data/local/tmp"};
    for (size_t i = 0; i < sizeof(read_only) / sizeof(read_only[0]); i++) sbx_policy_add(policy, read_only[i], SBX_READ);
    static const char *devices[] = {"/dev/kgsl-3d0", "/dev/dri", "/dev/mali0", "/dev/goldfish_pipe", "/dev/qemu_pipe",
                                    "/dev/goldfish_address_space", "/dev/ion", "/dev/dma_heap", "/dev/null",
                                    "/dev/zero", "/dev/urandom"};
    for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++)
        sbx_policy_add(policy, devices[i], SBX_READ | SBX_WRITE);
    sbx_policy_set_audit(policy, audit, NULL);
    if (sbx_broker_prepare(broker[0]) != 0) {
        perror("prepare");
        return 1;
    }

    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        close(broker[0]);
        close(control[0]);
        fcntl(broker[1], F_SETFD, 0);
        fcntl(control[1], F_SETFD, 0);
        char b[16], c[16];
        snprintf(b, sizeof(b), "%d", broker[1]);
        snprintf(c, sizeof(c), "%d", control[1]);
        char *child_argv[] = {argv[0], "--child", b, c, NULL};
        execv("/proc/self/exe", child_argv);
        perror("execv");
        _exit(127);
    }
    close(broker[1]);
    close(control[1]);
    if (sbx_broker_start(policy, broker[0]) != 0) {
        printf("parent: FAIL broker\n");
        return 1;
    }
    if (AHardwareBuffer_sendHandleToUnixSocket(buffer, control[0]) != 0) {
        printf("parent: FAIL sending the buffer\n");
        return 1;
    }
    char done = 0;
    ssize_t got = read(control[0], &done, 1);
    int status = 0;
    waitpid(pid, &status, 0);
    if (got != 1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("parent: FAIL the child did not finish (status 0x%x)\n", status);
        return 1;
    }
    void *pixels = NULL;
    if (AHardwareBuffer_lock(buffer, AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN, -1, NULL, &pixels) != 0 || !pixels) {
        printf("parent: FAIL locking the buffer for the CPU\n");
        return 1;
    }
    AHardwareBuffer_Desc actual;
    AHardwareBuffer_describe(buffer, &actual);
    const unsigned char *centre = (const unsigned char *) pixels + ((HEIGHT / 2) * actual.stride + WIDTH / 2) * 4;
    printf("parent: centre pixel RGBA %u %u %u %u\n", centre[0], centre[1], centre[2], centre[3]);
    int green = centre[0] < 16 && centre[1] > 240 && centre[2] < 16;
    AHardwareBuffer_unlock(buffer, NULL);
    AHardwareBuffer_release(buffer);
    printf("parent: %s; the broker refused %d request(s)\n",
           green ? "OK the locked-down child drew into the parent's buffer" : "FAIL the buffer is not green", refusals);
    return green ? 0 : 1;
}
