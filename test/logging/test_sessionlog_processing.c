#include "putty.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void modalfatalbox(const char *p, ...)
{
    va_list ap;
    fprintf(stderr, "FATAL ERROR: ");
    va_start(ap, p);
    vfprintf(stderr, p, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

const char *const appname = "test_sessionlog_processing";

char *platform_default_s(const char *name) { return NULL; }
bool platform_default_b(const char *name, bool def) { return def; }
int platform_default_i(const char *name, int def) { return def; }
FontSpec *platform_default_fontspec(const char *name) { return fontspec_new_default(); }
Filename *platform_default_filename(const char *name) { return filename_from_str(""); }
char *platform_get_x_display(void) { return NULL; }

static void lp_eventlog_noop(LogPolicy *lp, const char *event)
{
    (void)lp;
    (void)event;
}

static int lp_askappend_overwrite(LogPolicy *lp,
                                 Filename *filename,
                                 void (*callback)(void *ctx, int result),
                                 void *ctx)
{
    (void)lp;
    (void)filename;
    (void)callback;
    (void)ctx;
    return 2;
}

static void lp_logging_error_fatal(LogPolicy *lp, const char *event)
{
    (void)lp;
    fprintf(stderr, "logging error: %s\n", event);
    exit(1);
}

static bool lp_verbose_no(LogPolicy *lp)
{
    (void)lp;
    return false;
}

static const LogPolicyVtable kLogPolicyVtable = {
    .eventlog = lp_eventlog_noop,
    .askappend = lp_askappend_overwrite,
    .logging_error = lp_logging_error_fatal,
    .verbose = lp_verbose_no,
};

static LogPolicy kLogPolicy = {.vt = &kLogPolicyVtable};

static void die_errno(const char *what)
{
    fprintf(stderr, "fail: %s: %s\n", what, strerror(errno));
    exit(1);
}

static char *read_entire_file(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        die_errno("fopen");
    if (fseek(fp, 0, SEEK_END) != 0)
        die_errno("fseek");
    long sz = ftell(fp);
    if (sz < 0)
        die_errno("ftell");
    if (fseek(fp, 0, SEEK_SET) != 0)
        die_errno("fseek");

    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf)
        die_errno("malloc");
    const size_t got = fread(buf, 1, (size_t)sz, fp);
    if (got != (size_t)sz)
        die_errno("fread");
    fclose(fp);

    buf[sz] = '\0';
    *out_len = (size_t)sz;
    return buf;
}

static void expect(bool cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "fail: %s\n", msg);
        exit(1);
    }
}

static bool is_timestamp_prefix(const char *s, size_t len)
{
    if (len < 22)
        return false;
    if (s[0] != '[' || s[5] != '-' || s[8] != '-' || s[11] != ' ' ||
        s[14] != ':' || s[17] != ':' || s[20] != ']' || s[21] != ' ')
        return false;
    for (int i = 1; i <= 4; i++)
        if (!isdigit((unsigned char)s[i]))
            return false;
    for (int i = 6; i <= 7; i++)
        if (!isdigit((unsigned char)s[i]))
            return false;
    for (int i = 9; i <= 10; i++)
        if (!isdigit((unsigned char)s[i]))
            return false;
    for (int i = 12; i <= 13; i++)
        if (!isdigit((unsigned char)s[i]))
            return false;
    for (int i = 15; i <= 16; i++)
        if (!isdigit((unsigned char)s[i]))
            return false;
    for (int i = 18; i <= 19; i++)
        if (!isdigit((unsigned char)s[i]))
            return false;
    return true;
}

int main(void)
{
    const pid_t pid = getpid();
    char path[256];
    snprintf(path, sizeof(path), "/tmp/putty_test_sessionlog_%ld.log", (long)pid);
    unlink(path);

    Conf *conf = conf_new();
    conf_set_int(conf, CONF_protocol, PROT_RAW);
    conf_set_str(conf, CONF_host, "localhost");
    conf_set_int(conf, CONF_port, 0);
    conf_set_int(conf, CONF_logtype, LGTYP_ASCII);
    conf_set_int(conf, CONF_logxfovr, LGXF_OVR);
    conf_set_bool(conf, CONF_logheader, true);
    Filename *fn = filename_from_str(path);
    conf_set_filename(conf, CONF_logfilename, fn);
    filename_free(fn);

    LogContext *logctx = log_init(&kLogPolicy, conf);

    static const unsigned char kInput[] =
        "hello\r\n"
        "a\x1b[31mb\x1b[0m\r\n"
        "x\x1b]0;title\x07y\rz\n"
        "c\x1b[38;5;196mR\x1b[39m\n"
        "d\x1b[38;2;1;2;3mT\x1b[0m\n"
        "e\x1b[2J\x1b[Hf\n"
        "g\x1b]0;escst\x1b\\h\n";
    for (size_t i = 0; i < sizeof(kInput) - 1; i++)
        logtraffic(logctx, kInput[i], LGTYP_ASCII);
    logflush(logctx);

    log_free(logctx);
    conf_free(conf);

    size_t file_len = 0;
    char *file = read_entire_file(path, &file_len);
    expect(file_len > 0, "log file is empty");

    const char *header_end = memchr(file, '\n', file_len);
    expect(header_end != NULL, "log file missing header newline");
    expect(file[0] == '=' && file[1] == '~', "header line was modified");

    const char *p = header_end + 1;
    const char *end = file + file_len;

    const char *expected = "hello\nab\nxyz\ncR\ndT\nef\ngh\n";
    size_t expected_pos = 0;

    while (p < end) {
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end)
            break;

        const size_t line_len_with_nl = (size_t)(line_end - p) + 1;
        expect(is_timestamp_prefix(p, line_len_with_nl),
               "missing or malformed per-line timestamp prefix");

        const char *payload = p + 22;
        const size_t payload_len = line_len_with_nl - 22;
        expect(memchr(payload, '\x1b', payload_len) == NULL, "ansi escape not stripped");
        expect(memchr(payload, '\r', payload_len) == NULL, "carriage return not stripped");

        expect(expected_pos + payload_len <= strlen(expected), "output longer than expected");
        expect(memcmp(expected + expected_pos, payload, payload_len) == 0, "sanitised output mismatch");
        expected_pos += payload_len;

        p = line_end + 1;
    }

    expect(expected_pos == strlen(expected), "output shorter than expected");

    printf("success: session log filtering and timestamping matched expectations\n");
    free(file);
    unlink(path);
    return 0;
}
