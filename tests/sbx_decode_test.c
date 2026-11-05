/*
 * sbx_decode_test: FFmpeg decoding under SBX_LOCK_COMPUTE (Droidtop/tracker#906). For each sample, a
 * child decodes it from a memfd (custom I/O: no file, no protocol) with two decoding threads, locked
 * down before it reads a byte; the frame count and a checksum of the pictures go back through shared
 * memory. The same decode unconfined is the control: the two must agree.
 *
 *   sbx_decode_test <folder>   makes the samples there with the ffmpeg program, then decodes each
 *
 * Built only when FFmpeg's libraries are found. Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "sbx.h"

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/log.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct result {
    long frames;
    uint64_t checksum;
    int error;
};

static int input_fd;

static int read_packet(void *opaque, uint8_t *buffer, int size) {
    (void) opaque;
    ssize_t n = read(input_fd, buffer, (size_t) size);
    if (n == 0) return AVERROR_EOF;
    return n < 0 ? AVERROR(errno) : (int) n;
}

static int64_t seek(void *opaque, int64_t offset, int whence) {
    (void) opaque;
    if (whence == AVSEEK_SIZE) {
        struct stat st;
        return syscall(__NR_fstat, input_fd, &st) == 0 ? (int64_t) st.st_size : -1;
    }
    off_t at = lseek(input_fd, (off_t) offset, whence & ~AVSEEK_FORCE);
    return at < 0 ? AVERROR(errno) : (int64_t) at;
}

static void decode(struct result *out) {
    memset(out, 0, sizeof(*out));
    unsigned char *io_buffer = av_malloc(65536);
    AVIOContext *io = io_buffer ? avio_alloc_context(io_buffer, 65536, 0, NULL, read_packet, NULL, seek) : NULL;
    AVFormatContext *format = avformat_alloc_context();
    if (!io || !format) { out->error = 1; return; }
    format->pb = io;
    format->flags |= AVFMT_FLAG_CUSTOM_IO;
    if (avformat_open_input(&format, NULL, NULL, NULL) < 0) { out->error = 2; return; }
    if (avformat_find_stream_info(format, NULL) < 0) { out->error = 3; return; }
    const AVCodec *codec = NULL;
    int stream = av_find_best_stream(format, AVMEDIA_TYPE_VIDEO, -1, -1, &codec, 0);
    if (stream < 0) stream = av_find_best_stream(format, AVMEDIA_TYPE_AUDIO, -1, -1, &codec, 0);
    if (stream < 0 || !codec) { out->error = 4; return; }
    AVCodecContext *context = avcodec_alloc_context3(codec);
    if (!context || avcodec_parameters_to_context(context, format->streams[stream]->codecpar) < 0) { out->error = 5; return; }
    context->thread_count = 2;
    if (avcodec_open2(context, codec, NULL) < 0) { out->error = 6; return; }
    AVPacket *packet = av_packet_alloc();
    AVFrame *frame = av_frame_alloc();
    for (int draining = 0;;) {
        int sent;
        if (!draining) {
            int got = av_read_frame(format, packet);
            if (got < 0) {
                draining = 1;
                sent = avcodec_send_packet(context, NULL);
            } else {
                sent = packet->stream_index == stream ? avcodec_send_packet(context, packet) : 0;
                av_packet_unref(packet);
            }
        } else {
            sent = 0;
        }
        (void) sent;
        for (;;) {
            int received = avcodec_receive_frame(context, frame);
            if (received == AVERROR(EAGAIN)) break;
            if (received == AVERROR_EOF) goto done;
            if (received < 0) { out->error = 7; goto done; }
            out->frames++;
            /* The first row of the first plane (or the first bytes of audio): enough to tell two decodes apart. */
            int bytes = frame->width > 0 ? frame->width : (frame->linesize[0] < 64 ? frame->linesize[0] : 64);
            for (int x = 0; x < bytes && frame->data[0]; x++) {
                out->checksum = out->checksum * 31 + frame->data[0][x];
            }
            av_frame_unref(frame);
        }
    }
done:
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&context);
    avformat_close_input(&format);
}

/* Decodes path in a child (confined or not); the result through shared memory. -1 when the child did not finish. */
static int run(const char *path, int confined, struct result *out, int *signal_out) {
    int file = open(path, O_RDONLY | O_CLOEXEC);
    if (file < 0) return -1;
    int memfd = (int) syscall(__NR_memfd_create, "sample", 0);
    char chunk[65536];
    ssize_t n;
    while ((n = read(file, chunk, sizeof(chunk))) > 0) {
        if (write(memfd, chunk, (size_t) n) != n) return -1;
    }
    close(file);
    lseek(memfd, 0, SEEK_SET);
    int shared = (int) syscall(__NR_memfd_create, "result", 0);
    if (memfd < 0 || shared < 0 || ftruncate(shared, sizeof(struct result)) != 0) return -1;
    struct result *view = mmap(NULL, sizeof(struct result), PROT_READ | PROT_WRITE, MAP_SHARED, shared, 0);
    if (view == MAP_FAILED) return -1;
    memset(view, 0, sizeof(*view));
    view->error = -1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(60);
        input_fd = memfd;
        if (confined) {
            int keep[] = {memfd, shared};
            struct sbx_limit limits[] = {{RLIMIT_AS, 1ul << 30}, {RLIMIT_CPU, 30}};
            struct sbx_lockdown_options options = {.flags = SBX_LOCK_COMPUTE, .keep_fds = keep, .keep_count = 2,
                                                   .limits = limits, .limit_count = 2};
            if (sbx_lockdown(-1, &options) != 0) _exit(100);
        }
        struct result r;
        decode(&r);
        *view = r;
        _exit(0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    *signal_out = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    *out = *view;
    munmap(view, sizeof(struct result));
    close(memfd);
    close(shared);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int make_sample(const char *folder, const char *name, const char *const *codec_args, int audio, char *path,
                       size_t size) {
    snprintf(path, size, "%s/%s", folder, name);
    const char *argv[24];
    int n = 0;
    const char *video[] = {"ffmpeg", "-loglevel", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=320x240:rate=25",
                           "-t", "2", "-pix_fmt", "yuv420p"};
    const char *sound[] = {"ffmpeg", "-loglevel", "error", "-y", "-f", "lavfi", "-i", "sine=frequency=440:duration=2"};
    const char **head = audio ? sound : video;
    size_t head_count = audio ? sizeof(sound) / sizeof(sound[0]) : sizeof(video) / sizeof(video[0]);
    for (size_t i = 0; i < head_count; i++) argv[n++] = head[i];
    for (int i = 0; codec_args[i]; i++) argv[n++] = codec_args[i];
    argv[n++] = path;
    argv[n] = NULL;
    pid_t child = fork();
    if (child == 0) {
        execvp("ffmpeg", (char *const *) argv);
        _exit(127);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    av_log_set_level(AV_LOG_QUIET);
    const char *folder = argc > 1 ? argv[1] : "/tmp";
    /* Droidtop/tracker#913's correction to #906: H.264, HEVC and AAC are in. */
    struct sample {
        const char *name;
        const char *args[8];
        int audio;
    } samples[] = {
        {"h264.mp4", {"-c:v", "libx264", NULL}, 0},
        {"hevc.mp4", {"-c:v", "libx265", "-x265-params", "log-level=error", NULL}, 0},
        {"aac.m4a", {"-c:a", "aac", NULL}, 1},
        {"vp9.webm", {"-c:v", "libvpx-vp9", "-deadline", "realtime", NULL}, 0},
        {"av1.mkv", {"-c:v", "libaom-av1", "-cpu-used", "8", "-row-mt", "1", NULL}, 0},
        {"wmv2.asf", {"-c:v", "wmv2", NULL}, 0},
        {"mpeg2.mpg", {"-c:v", "mpeg2video", NULL}, 0},
    };
    int failures = 0, ran = 0;
    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
        char path[600];
        if (make_sample(folder, samples[i].name, samples[i].args, samples[i].audio, path, sizeof(path)) != 0) {
            printf("skip decode %s: ffmpeg could not make it here\n", samples[i].name);
            continue;
        }
        struct result plain, confined;
        int plain_signal = 0, confined_signal = 0;
        int a = run(path, 0, &plain, &plain_signal);
        int b = run(path, 1, &confined, &confined_signal);
        int ok = a == 0 && b == 0 && plain.error == 0 && confined.error == 0 &&
                 plain.frames == (samples[i].audio ? plain.frames : 50) && plain.frames > 0 &&
                 confined.frames == plain.frames && confined.checksum == plain.checksum;
        printf("%s decode %s under SBX_LOCK_COMPUTE: %ld frames (unconfined %ld), checksums %s",
               ok ? "ok  " : "FAIL", samples[i].name, confined.frames, plain.frames,
               confined.checksum == plain.checksum ? "agree" : "differ");
        if (!ok) printf(" [error %d, signal %d; unconfined error %d]", confined.error, confined_signal, plain.error);
        printf("\n");
        failures += !ok;
        ran++;
        unlink(path);
    }
    if (ran == 0) {
        printf("FAIL decode: no sample could be made (is ffmpeg installed?)\n");
        return 1;
    }
    printf(failures ? "%d failure(s)\n" : "all passed\n", failures);
    return failures ? 1 : 0;
}
