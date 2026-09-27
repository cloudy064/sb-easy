/* WireGuard hub management: X25519 keys, peer / managed-host provisioning,
 * client, hub and managed-host configs, kernel sync via `wg` / `ip` /
 * `iptables`, live stats, quota/expiry enforcement and QR SVGs.
 *
 * Port of cpp/src/wireguard.cpp. The generated texts (client/server/host
 * configs, the sing-box endpoint JSON and the QR SVG) are byte-identical to
 * the C++ ones, the same commands run with the same argv (posix_spawnp, no
 * shell) and failures carry the C++ exception messages. Kinds: ValidationError
 * -> SB_ERR_VALIDATION, NotFoundError -> SB_ERR_NOT_FOUND, nlohmann type_error
 * (mistyped saved settings) -> SB_ERR_BAD_JSON, process / filesystem
 * std::runtime_error -> SB_ERR_IO, other std::runtime_error -> SB_ERR_GENERIC. */
#include "sb/wireguard.h"

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <qrcodegen.h>

#include "sb/atomic_file.h"

extern char **environ;

#define S(x) ((x) ? (x) : "")

struct sb_wireguard {
    sb_store *store;
    sb_wireguard_options options;
};

/* ======================================================================
 * Processes (C++ run_command)
 * ====================================================================== */

typedef struct {
    int exit_code;
    sb_buf output; /* stdout and stderr, interleaved as written */
} command_result;

/* Spawns argv[0] through PATH (no shell) with stdout and stderr captured and
 * waits for it. Spawn and wait failures always fail; a non-zero exit code
 * fails only when `check` is set, exactly like the C++ run_command(). */
static int run_command(const char *const *argv, bool check, command_result *result, sb_err *err) {
    memset(result, 0, sizeof *result);
    result->exit_code = -1;
    if (!argv || !argv[0] || !argv[0][0])
        return sb_fail(err, SB_ERR_VALIDATION, "process command is empty");
    int output_pipe[2];
    if (pipe2(output_pipe, O_CLOEXEC) != 0)
        return sb_fail(err, SB_ERR_IO, "create process pipe failed: %s", strerror(errno));

    posix_spawn_file_actions_t actions;
    int init_error = posix_spawn_file_actions_init(&actions);
    if (init_error != 0) {
        close(output_pipe[0]);
        close(output_pipe[1]);
        return sb_fail(err, SB_ERR_IO, "initialize process failed: %s", strerror(init_error));
    }
    (void)posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDOUT_FILENO);
    (void)posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDERR_FILENO);
    (void)posix_spawn_file_actions_addclose(&actions, output_pipe[0]);
    (void)posix_spawn_file_actions_addclose(&actions, output_pipe[1]);

    pid_t process = 0;
    int spawn_error =
        posix_spawnp(&process, argv[0], &actions, NULL, (char *const *)argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(output_pipe[1]);
    if (spawn_error != 0) {
        close(output_pipe[0]);
        return sb_fail(err, SB_ERR_IO, "%s: %s", argv[0], strerror(spawn_error));
    }

    char buffer[4096];
    for (;;) {
        ssize_t count = read(output_pipe[0], buffer, sizeof buffer);
        if (count > 0) {
            sb_buf_append(&result->output, buffer, (size_t)count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        break;
    }
    close(output_pipe[0]);

    int status = 0;
    while (waitpid(process, &status, 0) < 0) {
        if (errno != EINTR) {
            sb_buf_free(&result->output);
            return sb_fail(err, SB_ERR_IO, "%s: wait failed", argv[0]);
        }
    }
    result->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (check && result->exit_code != 0) {
        sb_fail(err, SB_ERR_IO, "%s exited with code %d: %s", argv[0], result->exit_code,
                S(result->output.p));
        sb_buf_free(&result->output);
        return -1;
    }
    return 0;
}

/* run_command() when only the exit code matters (exit_code may be NULL). */
static int run(const char *const *argv, bool check, int *exit_code, sb_err *err) {
    command_result result;
    if (run_command(argv, check, &result, err) != 0) return -1;
    if (exit_code) *exit_code = result.exit_code;
    sb_buf_free(&result.output);
    return 0;
}

/* ======================================================================
 * Keys (standard base64 of the raw 32-byte X25519 keys)
 * ====================================================================== */

static char *encode_key(const unsigned char bytes[32], sb_err *err) {
    unsigned char encoded[45];
    int length = EVP_EncodeBlock(encoded, bytes, 32);
    if (length <= 0) {
        sb_fail(err, SB_ERR_GENERIC, "WireGuard base64 encoding failed");
        return NULL;
    }
    return sb_strndup((const char *)encoded, (size_t)length);
}

/* EVP_DecodeBlock-based check of the C++ base64_decode(): exactly 44
 * characters decoding to 33 bytes (no padding stripping) and ending in '='. */
static int decode_key(const char *value, unsigned char out[32], sb_err *err) {
    if (strlen(value) != 44U)
        return sb_fail(err, SB_ERR_VALIDATION, "WireGuard key must encode 32 bytes");
    unsigned char decoded[36] = {0};
    int length = EVP_DecodeBlock(decoded, (const unsigned char *)value, 44);
    if (length != 33 || value[43] != '=') {
        OPENSSL_cleanse(decoded, sizeof decoded);
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid WireGuard key");
    }
    memcpy(out, decoded, 32);
    OPENSSL_cleanse(decoded, sizeof decoded);
    return 0;
}

int sb_wireguard_generate_keypair(sb_wireguard_keypair *out, sb_err *err) {
    memset(out, 0, sizeof *out);
    unsigned char private_bytes[32];
    if (RAND_bytes(private_bytes, (int)sizeof private_bytes) != 1)
        return sb_fail(err, SB_ERR_GENERIC, "WireGuard key generation failed");
    EVP_PKEY *key =
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_bytes, sizeof private_bytes);
    if (!key) {
        OPENSSL_cleanse(private_bytes, sizeof private_bytes);
        return sb_fail(err, SB_ERR_GENERIC, "WireGuard X25519 private key failed");
    }
    unsigned char public_bytes[32];
    size_t public_size = sizeof public_bytes;
    bool derived = EVP_PKEY_get_raw_public_key(key, public_bytes, &public_size) == 1 &&
                   public_size == sizeof public_bytes;
    EVP_PKEY_free(key);
    if (!derived) {
        OPENSSL_cleanse(private_bytes, sizeof private_bytes);
        return sb_fail(err, SB_ERR_GENERIC, "WireGuard public key derivation failed");
    }
    out->private_key = encode_key(private_bytes, err);
    OPENSSL_cleanse(private_bytes, sizeof private_bytes);
    if (!out->private_key) return -1;
    out->public_key = encode_key(public_bytes, err);
    if (!out->public_key) {
        sb_wireguard_keypair_free(out);
        return -1;
    }
    return 0;
}

char *sb_wireguard_generate_preshared_key(sb_err *err) {
    unsigned char bytes[32];
    if (RAND_bytes(bytes, (int)sizeof bytes) != 1) {
        sb_fail(err, SB_ERR_GENERIC, "WireGuard preshared key generation failed");
        return NULL;
    }
    char *key = encode_key(bytes, err);
    OPENSSL_cleanse(bytes, sizeof bytes);
    return key;
}

char *sb_wireguard_public_key_from_private(const char *private_key, sb_err *err) {
    unsigned char private_bytes[32];
    if (decode_key(S(private_key), private_bytes, err) != 0) return NULL;
    EVP_PKEY *key =
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_bytes, sizeof private_bytes);
    OPENSSL_cleanse(private_bytes, sizeof private_bytes);
    if (!key) {
        sb_fail(err, SB_ERR_VALIDATION, "Invalid WireGuard private key");
        return NULL;
    }
    unsigned char public_bytes[32];
    size_t public_size = sizeof public_bytes;
    bool derived = EVP_PKEY_get_raw_public_key(key, public_bytes, &public_size) == 1 &&
                   public_size == sizeof public_bytes;
    EVP_PKEY_free(key);
    if (!derived) {
        sb_fail(err, SB_ERR_VALIDATION, "Invalid WireGuard private key");
        return NULL;
    }
    return encode_key(public_bytes, err);
}

/* ======================================================================
 * Addresses
 * ====================================================================== */

/* subnet_cidr(): "10.59.32.1/24" -> "10.59.32.0/24"; other prefixes keep the
 * host part; an address without '/' is returned unchanged. */
static char *subnet_cidr(const char *address) {
    const char *slash = strchr(address, '/');
    if (!slash) return sb_strdup(address);
    const char *prefix = slash + 1;
    if (strcmp(prefix, "24") == 0) {
        const char *dot = NULL;
        for (const char *p = address; p < slash; ++p)
            if (*p == '.') dot = p;
        if (dot) return sb_asprintf("%.*s0/%s", (int)(dot - address + 1), address, prefix);
    }
    return sb_asprintf("%.*s/%s", (int)(slash - address), address, prefix);
}

/* peer_ip(): the address without its prefix length. */
static char *peer_ip(const char *address) { return sb_strndup(address, strcspn(address, "/")); }

/* endpoint_port(): the digits after the last ':' as a non-zero uint16
 * (std::from_chars must consume the whole remainder). */
static bool endpoint_port(const char *endpoint, uint16_t *port) {
    if (!endpoint) return false;
    const char *colon = strrchr(endpoint, ':');
    if (!colon) return false;
    const char *text = colon + 1;
    if (!*text) return false;
    unsigned long value = 0;
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        value = value * 10U + (unsigned long)(*p - '0');
        if (value > 65535U) return false;
    }
    if (value == 0U) return false;
    *port = (uint16_t)value;
    return true;
}

/* ======================================================================
 * Numbers and time (std::from_chars / std::get_time semantics)
 * ====================================================================== */

/* std::from_chars(first, last, int64&) as used by parse_stats(), whose result
 * C++ ignores: the value is stored whenever a valid in-range prefix was read
 * (trailing characters and all), and left untouched on invalid input or
 * overflow. */
static void from_chars_i64_prefix(const char *s, size_t len, int64_t *out) {
    size_t i = 0;
    bool negative = false;
    if (i < len && s[i] == '-') {
        negative = true;
        ++i;
    }
    size_t digits = i;
    uint64_t magnitude = 0;
    bool overflow = false;
    for (; i < len && s[i] >= '0' && s[i] <= '9'; ++i) {
        unsigned digit = (unsigned)(s[i] - '0');
        if (magnitude > (UINT64_MAX - digit) / 10U)
            overflow = true;
        else
            magnitude = magnitude * 10U + digit;
    }
    if (i == digits) return;
    uint64_t limit = negative ? (uint64_t)INT64_MAX + 1U : (uint64_t)INT64_MAX;
    if (overflow || magnitude > limit) return;
    if (!negative)
        *out = (int64_t)magnitude;
    else
        *out = magnitude == limit ? INT64_MIN : -(int64_t)magnitude;
}

/* std::from_chars(first, last, int&) that must consume the whole text. */
static bool from_chars_int_exact(const char *s, size_t len, int *out) {
    size_t i = 0;
    bool negative = false;
    if (i < len && s[i] == '-') {
        negative = true;
        ++i;
    }
    if (i == len) return false;
    long long value = 0;
    for (; i < len; ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        value = value * 10 + (s[i] - '0');
        if (value > (long long)INT32_MAX + 1) return false;
    }
    if (negative) value = -value;
    if (value < INT32_MIN || value > INT32_MAX) return false;
    *out = (int)value;
    return true;
}

/* "C" locale ctype<char> predicates used by libstdc++'s time_get. */
static bool c_isspace(char c) { return c == ' ' || (c >= '\t' && c <= '\r'); }
static char c_tolower(char c) { return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c; }
static char c_toupper(char c) { return c >= 'a' && c <= 'z' ? (char)(c - 'a' + 'A') : c; }

/* libstdc++ time_get::_M_extract_num(). */
static bool extract_num(const char *s, size_t n, size_t *pos, int min, int max, size_t len,
                        int *member) {
    size_t p = *pos, i = 0;
    int value = 0;
    for (; p < n && i < len; ++p, ++i) {
        char c = s[p];
        if (c < '0' || c > '9') break;
        value = value * 10 + (c - '0');
        if (value > max) break;
    }
    *pos = p;
    if (i && value >= min && value <= max) {
        *member = value;
        return true;
    }
    return false;
}

/* `std::istringstream{text} >> std::get_time(tm, "%Y-%m-%dT%H:%M:%S")` with
 * libstdc++: the sentry skips leading whitespace, literals compare
 * case-insensitively, %d skips one leading space, and input running out right
 * after a conversion ends parsing successfully (eofbit only), leaving the
 * remaining fields zero. Returns false where C++ would set failbit. */
static bool get_time_rfc3339(const char *s, size_t n, struct tm *tm) {
    size_t pos = 0;
    while (pos < n && c_isspace(s[pos])) ++pos;
    if (pos == n) return false;
    static const char format[] = "%Y-%m-%dT%H:%M:%S";
    for (const char *f = format; *f;) {
        if (pos == n) return false; /* eofbit | failbit */
        if (*f != '%') {
            if (c_tolower(s[pos]) != c_tolower(*f) && c_toupper(s[pos]) != c_toupper(*f))
                return false;
            ++pos;
            ++f;
            continue;
        }
        int value = 0;
        bool ok = false;
        switch (f[1]) {
        case 'Y':
            ok = extract_num(s, n, &pos, 0, 9999, 4, &value);
            if (ok) tm->tm_year = value - 1900;
            break;
        case 'm':
            ok = extract_num(s, n, &pos, 1, 12, 2, &value);
            if (ok) tm->tm_mon = value - 1;
            break;
        case 'd':
            if (c_isspace(s[pos])) ++pos;
            ok = extract_num(s, n, &pos, 1, 31, 2, &value);
            if (ok) tm->tm_mday = value;
            break;
        case 'H':
            ok = extract_num(s, n, &pos, 0, 23, 2, &value);
            if (ok) tm->tm_hour = value;
            break;
        case 'M':
            ok = extract_num(s, n, &pos, 0, 59, 2, &value);
            if (ok) tm->tm_min = value;
            break;
        default: /* 'S' */
            ok = extract_num(s, n, &pos, 0, 60, 2, &value);
            if (ok) tm->tm_sec = value;
            break;
        }
        if (!ok) return false;
        f += 2;
        if (pos == n) return true; /* eofbit: stop without failing */
    }
    return true;
}

/* C++ parse_rfc3339(): the first 19 characters through get_time + timegm,
 * then an optional "±hh:mm" offset found at or after index 19. */
static bool parse_rfc3339(const char *value, int64_t *seconds_out) {
    size_t length = strlen(value);
    if (length < 19U) return false;
    struct tm parsed;
    memset(&parsed, 0, sizeof parsed);
    if (!get_time_rfc3339(value, 19U, &parsed)) return false;
    int64_t seconds = (int64_t)timegm(&parsed);
    size_t zone = 19U + strcspn(value + 19, "Z+-");
    if (zone < length && value[zone] != 'Z' && zone + 5U < length && value[zone + 3U] == ':') {
        int hours = 0, minutes = 0;
        if (!from_chars_int_exact(value + zone + 1U, 2U, &hours) ||
            !from_chars_int_exact(value + zone + 4U, 2U, &minutes))
            return false;
        int64_t offset = (int64_t)hours * 3600 + (int64_t)minutes * 60;
        seconds += value[zone] == '+' ? -offset : offset;
    }
    *seconds_out = seconds;
    return true;
}

bool sb_wireguard_peer_expired(const sb_wireguard_peer *peer) {
    if (!peer || sb_str_empty(peer->expire_at)) return false;
    int64_t seconds = 0;
    if (!parse_rfc3339(peer->expire_at, &seconds)) return false;
    /* system_clock::from_time_t(seconds) < system_clock::now(), compared in
     * int64 nanoseconds. from_time_t overflows past year 2262; the C++ build
     * wraps modulo 2^64 there, so wrap identically (without C UB). */
    int64_t expiration = (int64_t)((uint64_t)seconds * UINT64_C(1000000000));
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    int64_t current =
        (int64_t)((uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec);
    return expiration < current;
}

/* ======================================================================
 * QR codes
 * ====================================================================== */

/* The qrcodegen::data_too_long message QrCode::encodeSegments() throws after
 * trying version 40 at ECC MEDIUM with the single segment makeSegments()
 * picks (numeric, alphanumeric or byte mode). */
static void qr_too_long(const char *text, sb_err *err) {
    size_t n = strlen(text);
    int count_bits;
    size_t data_bits;
    if (qrcodegen_isNumeric(text)) {
        count_bits = 14;
        data_bits = n / 3U * 10U + (n % 3U ? n % 3U * 3U + 1U : 0U);
    } else if (qrcodegen_isAlphanumeric(text)) {
        count_bits = 13;
        data_bits = n / 2U * 11U + n % 2U * 6U;
    } else {
        count_bits = 16;
        data_bits = n * 8U;
    }
    const int capacity_bits = 2334 * 8; /* getNumDataCodewords(40, MEDIUM) * 8 */
    if (n >= ((size_t)1 << count_bits) || data_bits > (size_t)(INT32_MAX - 4 - count_bits))
        sb_fail(err, SB_ERR_GENERIC, "Segment too long");
    else
        sb_fail(err, SB_ERR_GENERIC, "Data length = %zu bits, Max capacity = %d bits",
                data_bits + 4U + (size_t)count_bits, capacity_bits);
}

char *sb_qr_svg_for_text(const char *text, sb_err *err) {
    const char *value = S(text);
    uint8_t *qrcode = sb_xmalloc(qrcodegen_BUFFER_LEN_MAX);
    uint8_t *temporary = sb_xmalloc(qrcodegen_BUFFER_LEN_MAX);
    /* QrCode::encodeText(text, Ecc::MEDIUM): versions 1..40, automatic mask,
     * ECC boosted when it fits. */
    bool encoded = qrcodegen_encodeText(value, temporary, qrcode, qrcodegen_Ecc_MEDIUM,
                                        qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                                        qrcodegen_Mask_AUTO, true);
    free(temporary);
    if (!encoded) {
        free(qrcode);
        qr_too_long(value, err);
        return NULL;
    }
    enum { border = 4 };
    int size = qrcodegen_getSize(qrcode);
    sb_buf svg = {0};
    sb_buf_printf(&svg,
                  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                  "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 %d %d\" "
                  "shape-rendering=\"crispEdges\">"
                  "<rect width=\"100%%\" height=\"100%%\" fill=\"#fff\"/>"
                  "<path d=\"",
                  size + border * 2, size + border * 2);
    char module[48];
    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            if (!qrcodegen_getModule(qrcode, x, y)) continue;
            int length = snprintf(module, sizeof module, "M%d,%dh1v1h-1z", x + border, y + border);
            sb_buf_append(&svg, module, (size_t)length);
        }
    }
    sb_buf_puts(&svg, "\" fill=\"#000\"/></svg>");
    free(qrcode);
    return sb_buf_detach(&svg);
}

/* ======================================================================
 * Options, key pairs and stats values
 * ====================================================================== */

void sb_wireguard_options_init(sb_wireguard_options *o) {
    memset(o, 0, sizeof *o);
    o->enabled = false;
    o->interface = sb_strdup("wg0");
    o->port = 51820;
    o->address = sb_strdup("10.59.32.1/24");
    o->dns = sb_strdup("10.59.32.1");
    o->mtu = 1420;
    o->external_hostname = sb_strdup("127.0.0.1");
    o->egress_interface = sb_strdup("eth0");
    o->config_directory = sb_strdup("/etc/wireguard");
}

void sb_wireguard_options_free(sb_wireguard_options *o) {
    if (!o) return;
    free(o->interface);
    free(o->address);
    free(o->dns);
    free(o->external_hostname);
    free(o->egress_interface);
    free(o->config_directory);
    memset(o, 0, sizeof *o);
}

/* dst is overwritten (not freed first). */
void sb_wireguard_options_copy(sb_wireguard_options *dst, const sb_wireguard_options *src) {
    *dst = *src;
    dst->interface = sb_strdup(src->interface);
    dst->address = sb_strdup(src->address);
    dst->dns = sb_strdup(src->dns);
    dst->external_hostname = sb_strdup(src->external_hostname);
    dst->egress_interface = sb_strdup(src->egress_interface);
    dst->config_directory = sb_strdup(src->config_directory);
}

void sb_wireguard_keypair_free(sb_wireguard_keypair *k) {
    if (!k) return;
    free(k->private_key);
    free(k->public_key);
    memset(k, 0, sizeof *k);
}

void sb_wireguard_peer_stats_free(sb_wireguard_peer_stats *s) {
    if (!s) return;
    free(s->public_key);
    free(s->endpoint);
    memset(s, 0, sizeof *s);
}

sbj *sb_wireguard_peer_stats_to_json(const sb_wireguard_peer_stats *s) {
    sbj *value = sbj_object();
    sbj_set_str(value, "public_key", S(s->public_key));
    sbj_set(value, "endpoint", s->endpoint ? sbj_str(s->endpoint) : sbj_null());
    sbj_set(value, "latest_handshake",
            s->has_latest_handshake ? sbj_int(s->latest_handshake) : sbj_null());
    sbj_set_int(value, "transfer_rx", s->transfer_rx);
    sbj_set_int(value, "transfer_tx", s->transfer_tx);
    return value;
}

void sb_wireguard_peer_stats_vec_free(sb_wireguard_peer_stats_vec *v) {
    if (!v) return;
    for (size_t i = 0; i < v->len; ++i) sb_wireguard_peer_stats_free(&v->items[i]);
    free(v->items);
    memset(v, 0, sizeof *v);
}

sbj *sb_wireguard_peer_stats_vec_to_json(const sb_wireguard_peer_stats_vec *v) {
    sbj *array = sbj_array();
    for (size_t i = 0; v && i < v->len; ++i)
        sbj_arr_push(array, sb_wireguard_peer_stats_to_json(&v->items[i]));
    return array;
}

static sb_wireguard_peer_stats *stats_push(sb_wireguard_peer_stats_vec *v) {
    if (v->len == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 8;
        v->items = sb_xrealloc(v->items, v->cap * sizeof *v->items);
    }
    sb_wireguard_peer_stats *s = &v->items[v->len++];
    memset(s, 0, sizeof *s);
    return s;
}

/* ======================================================================
 * Stats (`wg show <interface> dump`)
 * ====================================================================== */

/* WireGuardService::parse_stats() over dump[0, len): one peer per line with
 * at least 8 tab-separated fields (the interface line has 4). */
static void parse_stats(const char *dump, size_t len, sb_wireguard_peer_stats_vec *out) {
    size_t pos = 0;
    while (pos < len) {
        const char *line = dump + pos;
        const char *newline = memchr(line, '\n', len - pos);
        size_t line_len = newline ? (size_t)(newline - line) : len - pos;
        pos += line_len + (newline ? 1U : 0U);

        const char *fields[8];
        size_t lengths[8];
        size_t count = 0, start = 0;
        for (size_t i = 0;; ++i) {
            if (i == line_len || line[i] == '\t') {
                if (count < 8U) {
                    fields[count] = line + start;
                    lengths[count] = i - start;
                }
                ++count;
                start = i + 1U;
                if (i == line_len) break;
            }
        }
        if (count < 8U) continue;

        int64_t handshake = 0, received = 0, transmitted = 0;
        from_chars_i64_prefix(fields[4], lengths[4], &handshake);
        from_chars_i64_prefix(fields[5], lengths[5], &received);
        from_chars_i64_prefix(fields[6], lengths[6], &transmitted);
        sb_wireguard_peer_stats *s = stats_push(out);
        s->public_key = sb_strndup(fields[0], lengths[0]);
        bool no_endpoint =
            lengths[2] == 0U || (lengths[2] == 6U && memcmp(fields[2], "(none)", 6) == 0);
        s->endpoint = no_endpoint ? NULL : sb_strndup(fields[2], lengths[2]);
        s->has_latest_handshake = handshake > 0;
        s->latest_handshake = handshake > 0 ? handshake : 0;
        s->transfer_rx = received;
        s->transfer_tx = transmitted;
    }
}

int sb_wireguard_parse_stats(const char *dump, sb_wireguard_peer_stats_vec *out, sb_err *err) {
    const char *text = S(dump);
    parse_stats(text, strlen(text), out);
    return 0;
}

/* ======================================================================
 * Service
 * ====================================================================== */

static void default_string(char **slot, const char *fallback) {
    if (!*slot) *slot = sb_strdup(fallback);
}

sb_wireguard *sb_wireguard_new(sb_store *store, const sb_wireguard_options *options) {
    if (!store) return NULL; /* C++: "WireGuard store is required" */
    sb_wireguard *wg = sb_xcalloc(1, sizeof *wg);
    wg->store = store;
    if (!options) {
        sb_wireguard_options_init(&wg->options);
        return wg;
    }
    sb_wireguard_options_copy(&wg->options, options);
    /* Unset (NULL) strings take the C++ member defaults. */
    default_string(&wg->options.interface, "wg0");
    default_string(&wg->options.address, "10.59.32.1/24");
    default_string(&wg->options.dns, "10.59.32.1");
    default_string(&wg->options.external_hostname, "127.0.0.1");
    default_string(&wg->options.egress_interface, "eth0");
    default_string(&wg->options.config_directory, "/etc/wireguard");
    return wg;
}

void sb_wireguard_free(sb_wireguard *wg) {
    if (!wg) return;
    sb_wireguard_options_free(&wg->options);
    free(wg);
}

/* nlohmann's json::value(key, default) conversion failure. */
static int type_error(sb_err *err, const char *expected, const sbj *value) {
    return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.type_error.302] type must be %s, but is %s",
                   expected, sbj_type_name(value));
}

/* saved.value(key, *slot) for a string member. */
static int saved_string(const sbj *saved, const char *key, char **slot, sb_err *err) {
    const sbj *value = sbj_get(saved, key);
    if (!value) return 0;
    if (!sbj_is_string(value)) return type_error(err, "string", value);
    sb_str_set(slot, value->v.str.ptr);
    return 0;
}

/* static_cast<std::uint64_t>(double) as GCC compiles it for the C++ build.
 * Values outside [0, 2^64) are UB in C++; what they produce there depends on
 * the target: AArch64 uses a saturating fcvtzu (negative/NaN -> 0, too large
 * -> 2^64-1), x86-64 uses cvttsd2si with a 2^63 rebias (-1.5 -> 2^64-1,
 * NaN and values below -2^63 -> 2^63, values >= 2^64 -> 0). */
static uint64_t double_to_u64(double value) {
#if defined(__aarch64__)
    if (!(value > 0.0)) return 0U;
    return value < 18446744073709551616.0 ? (uint64_t)value : UINT64_MAX;
#else
    const double two63 = 9223372036854775808.0;
    const uint64_t indefinite = UINT64_C(0x8000000000000000);
    if (value != value) return indefinite;
    if (value < two63) return value >= -two63 ? (uint64_t)(int64_t)value : indefinite;
    value -= two63;
    return value < two63 ? (uint64_t)(int64_t)value ^ indefinite : 0U;
#endif
}

/* saved.value(key, static_cast<std::uint64_t>(fallback)). */
static int saved_u64(const sbj *saved, const char *key, uint64_t fallback, uint64_t *out,
                     sb_err *err) {
    const sbj *value = sbj_get(saved, key);
    if (!value) {
        *out = fallback;
        return 0;
    }
    switch (value->type) {
    case SBJ_INT: *out = (uint64_t)value->v.i; return 0;
    case SBJ_UINT: *out = value->v.u; return 0;
    case SBJ_FLOAT: *out = double_to_u64(value->v.f); return 0;
    default: return type_error(err, "number", value);
    }
}

int sb_wireguard_runtime_options(sb_wireguard *wg, sb_wireguard_options *out, sb_err *err) {
    sb_wireguard_options runtime;
    sb_wireguard_options_copy(&runtime, &wg->options);
    sbj *saved = NULL;
    int found = sb_store_app_setting(wg->store, "wireguard_interface", &saved, err);
    int rc = found < 0 ? -1 : 0;
    if (found == 1 && sbj_is_object(saved)) {
        uint64_t port = 0, mtu = 0;
        if (saved_string(saved, "interface", &runtime.interface, err) != 0 ||
            saved_string(saved, "address", &runtime.address, err) != 0 ||
            saved_string(saved, "dns", &runtime.dns, err) != 0 ||
            saved_u64(saved, "listen_port", runtime.port, &port, err) != 0 ||
            saved_u64(saved, "mtu", runtime.mtu, &mtu, err) != 0) {
            rc = -1;
        } else {
            if (port > 0U && port <= 65535U) runtime.port = (uint16_t)port;
            if (mtu <= 65535U) runtime.mtu = (uint32_t)mtu;
        }
    }
    sbj_free(saved);
    if (rc != 0) {
        sb_wireguard_options_free(&runtime);
        memset(out, 0, sizeof *out);
        return -1;
    }
    *out = runtime;
    return 0;
}

/* server_keypair(): the persisted wg_server_key (public key derived when
 * missing), or a freshly generated pair that is persisted first. */
static int server_keypair(sb_wireguard *wg, sb_wireguard_keypair *out, sb_err *err) {
    memset(out, 0, sizeof *out);
    sbj *saved = NULL;
    int found = sb_store_app_setting(wg->store, "wg_server_key", &saved, err);
    if (found < 0) return -1;
    if (found == 1 && sbj_is_object(saved)) {
        const sbj *private_value = sbj_get(saved, "private_key");
        const sbj *public_value = sbj_get(saved, "public_key");
        if (private_value && !sbj_is_string(private_value)) {
            type_error(err, "string", private_value);
            sbj_free(saved);
            return -1;
        }
        if (public_value && !sbj_is_string(public_value)) {
            type_error(err, "string", public_value);
            sbj_free(saved);
            return -1;
        }
        const char *private_key = private_value ? private_value->v.str.ptr : "";
        const char *public_key = public_value ? public_value->v.str.ptr : "";
        if (private_key[0]) {
            out->public_key = public_key[0] ? sb_strdup(public_key)
                                            : sb_wireguard_public_key_from_private(private_key, err);
            if (!out->public_key) {
                sbj_free(saved);
                return -1;
            }
            out->private_key = sb_strdup(private_key);
            sbj_free(saved);
            return 0;
        }
    }
    sbj_free(saved);
    sb_wireguard_keypair generated;
    if (sb_wireguard_generate_keypair(&generated, err) != 0) return -1;
    sbj *value = sbj_object();
    sbj_set_str(value, "private_key", generated.private_key);
    sbj_set_str(value, "public_key", generated.public_key);
    int rc = sb_store_set_app_setting(wg->store, "wg_server_key", value, err);
    sbj_free(value);
    if (rc != 0) {
        sb_wireguard_keypair_free(&generated);
        return -1;
    }
    *out = generated;
    return 0;
}

char *sb_wireguard_server_public_key(sb_wireguard *wg, sb_err *err) {
    sb_wireguard_keypair keys;
    if (server_keypair(wg, &keys, err) != 0) return NULL;
    char *public_key = keys.public_key;
    keys.public_key = NULL;
    sb_wireguard_keypair_free(&keys);
    return public_key;
}

int sb_wireguard_stats(sb_wireguard *wg, sb_wireguard_peer_stats_vec *out, sb_err *err) {
    sb_wireguard_options runtime;
    if (sb_wireguard_runtime_options(wg, &runtime, err) != 0) return -1;
    const char *argv[] = {"wg", "show", runtime.interface, "dump", NULL};
    command_result result;
    int rc = run_command(argv, true, &result, err);
    if (rc == 0) parse_stats(S(result.output.p), result.output.len, out);
    sb_buf_free(&result.output);
    sb_wireguard_options_free(&runtime);
    return rc;
}

char *sb_wireguard_client_config(sb_wireguard *wg, const sb_wireguard_peer *peer, sb_err *err) {
    return sb_wireguard_client_config_n(wg, peer, NULL, err);
}

char *sb_wireguard_client_config_n(sb_wireguard *wg, const sb_wireguard_peer *peer, size_t *len, sb_err *err) {
    if (len) *len = 0;
    sb_wireguard_options runtime;
    if (sb_wireguard_runtime_options(wg, &runtime, err) != 0) return NULL;
    char *server_public = sb_wireguard_server_public_key(wg, err);
    if (!server_public) {
        sb_wireguard_options_free(&runtime);
        return NULL;
    }
    sb_buf config = {0};
    sb_buf_puts(&config, "# Client: ");
    sb_buf_append(&config, S(peer->name), peer->name_len);
    sb_buf_puts(&config, "\n[Interface]\n");
    sb_buf_printf(&config, "PrivateKey = %s\n", S(peer->private_key));
    sb_buf_printf(&config, "Address = %s\n", S(peer->address));
    sb_buf_printf(&config, "DNS = %s\n", S(peer->dns));
    if (runtime.mtu > 0U) sb_buf_printf(&config, "MTU = %u\n", (unsigned)runtime.mtu);
    sb_buf_printf(&config, "\n[Peer]\nPublicKey = %s\n", server_public);
    if (!sb_str_empty(peer->preshared_key))
        sb_buf_printf(&config, "PresharedKey = %s\n", peer->preshared_key);
    sb_buf_printf(&config, "AllowedIPs = %s\n", S(peer->allowed_ips));
    sb_buf_printf(&config, "Endpoint = %s:%u\n", S(runtime.external_hostname),
                  (unsigned)runtime.port);
    if (peer->persistent_keepalive > 0)
        sb_buf_printf(&config, "PersistentKeepalive = %d\n", (int)peer->persistent_keepalive);
    free(server_public);
    sb_wireguard_options_free(&runtime);
    if (len) *len = config.len;
    return sb_buf_detach(&config);
}

/* First peer linked to host_id (std::ranges::find on the optional host_id). */
static sb_wireguard_peer *find_host_peer(const sb_wireguard_peer_vec *peers, const char *host_id) {
    for (size_t i = 0; i < peers->len; ++i)
        if (peers->items[i].host_id && strcmp(peers->items[i].host_id, S(host_id)) == 0)
            return &peers->items[i];
    return NULL;
}

int sb_wireguard_client_endpoint(sb_wireguard *wg, const sb_host *host, sbj **out, sb_err *err) {
    sb_wireguard_peer_vec peers = {0};
    if (sb_store_list_wireguard_peers(wg->store, &peers, err) != 0) {
        sb_wireguard_peer_vec_free(&peers);
        return -1;
    }
    const sb_wireguard_peer *found = find_host_peer(&peers, host->id);
    if (!found || !found->enabled || sb_wireguard_peer_expired(found)) {
        sb_wireguard_peer_vec_free(&peers);
        return 0;
    }
    sb_wireguard_options runtime;
    if (sb_wireguard_runtime_options(wg, &runtime, err) != 0) {
        sb_wireguard_peer_vec_free(&peers);
        return -1;
    }
    char *server_public = sb_wireguard_server_public_key(wg, err);
    if (!server_public) {
        sb_wireguard_options_free(&runtime);
        sb_wireguard_peer_vec_free(&peers);
        return -1;
    }

    sbj *remote = sbj_object();
    sbj_set_str(remote, "address", S(runtime.external_hostname));
    sbj_set(remote, "port", sbj_uint(runtime.port));
    sbj_set(remote, "public_key", sbj_str_take(server_public));
    sbj *allowed_ips = sbj_array();
    sbj_arr_push(allowed_ips, sbj_str_take(subnet_cidr(S(runtime.address))));
    sbj_set(remote, "allowed_ips", allowed_ips);
    sbj_set_int(remote, "persistent_keepalive_interval", found->persistent_keepalive);
    if (!sb_str_empty(found->preshared_key))
        sbj_set_str(remote, "pre_shared_key", found->preshared_key);
    sbj *remotes = sbj_array();
    sbj_arr_push(remotes, remote);

    sbj *endpoint = sbj_object();
    sbj_set_str(endpoint, "type", "wireguard");
    sbj_set_str(endpoint, "tag", "sb-easy-network");
    sbj *address = sbj_array();
    sbj_arr_push(address, sbj_str(S(found->address)));
    sbj_set(endpoint, "address", address);
    sbj_set_str(endpoint, "private_key", S(found->private_key));
    sbj_set(endpoint, "peers", remotes);
    if (runtime.mtu > 0U) sbj_set(endpoint, "mtu", sbj_uint(runtime.mtu));

    sb_wireguard_options_free(&runtime);
    sb_wireguard_peer_vec_free(&peers);
    *out = endpoint;
    return 1;
}

char *sb_wireguard_qr_svg(sb_wireguard *wg, const sb_wireguard_peer *peer, sb_err *err) {
    char *config = sb_wireguard_client_config(wg, peer, err);
    if (!config) return NULL;
    char *svg = sb_qr_svg_for_text(config, err);
    free(config);
    return svg;
}

static const sb_wireguard_peer_stats *find_stats(const sb_wireguard_peer_stats_vec *stats,
                                                 const char *public_key) {
    for (size_t i = 0; i < stats->len; ++i)
        if (strcmp(S(stats->items[i].public_key), S(public_key)) == 0) return &stats->items[i];
    return NULL;
}

char *sb_wireguard_server_config(sb_wireguard *wg, sb_err *err) {
    return sb_wireguard_server_config_n(wg, NULL, err);
}

char *sb_wireguard_server_config_n(sb_wireguard *wg, size_t *len, sb_err *err) {
    if (len) *len = 0;
    sb_wireguard_options runtime;
    if (sb_wireguard_runtime_options(wg, &runtime, err) != 0) return NULL;
    /* Live counters only enforce quotas; failures (no interface, no `wg`)
     * are ignored as in C++. */
    sb_wireguard_peer_stats_vec current = {0};
    if (sb_wireguard_stats(wg, &current, NULL) != 0) sb_wireguard_peer_stats_vec_free(&current);

    char *result = NULL;
    sb_buf config = {0};
    sb_wireguard_peer_vec peers = {0};
    sb_wireguard_keypair keys;
    if (server_keypair(wg, &keys, err) != 0) goto done;
    sb_buf_printf(&config, "# Generated by sb-easy\n\n[Interface]\nPrivateKey = %s\n",
                  keys.private_key);
    sb_buf_printf(&config, "ListenPort = %u\n", (unsigned)runtime.port);
    sb_wireguard_keypair_free(&keys);
    if (sb_store_list_wireguard_peers(wg->store, &peers, err) != 0) goto done;
    for (size_t i = 0; i < peers.len; ++i) {
        const sb_wireguard_peer *peer = &peers.items[i];
        if (!peer->enabled || sb_wireguard_peer_expired(peer)) continue;
        const sb_wireguard_peer_stats *found = find_stats(&current, peer->public_key);
        /* int64 sum wrapping like the C++ build instead of overflowing. */
        if (peer->quota_bytes > 0 && found &&
            (int64_t)((uint64_t)found->transfer_rx + (uint64_t)found->transfer_tx) >=
                peer->quota_bytes)
            continue;
        sb_buf_puts(&config, "\n# Client: ");
        sb_buf_append(&config, S(peer->name), peer->name_len);
        sb_buf_printf(&config, "\n[Peer]\nPublicKey = %s\n", S(peer->public_key));
        if (!sb_str_empty(peer->preshared_key))
            sb_buf_printf(&config, "PresharedKey = %s\n", peer->preshared_key);
        char *ip = peer_ip(S(peer->address));
        sb_buf_printf(&config, "AllowedIPs = %s/32\n", ip);
        free(ip);
        if (peer->persistent_keepalive > 0)
            sb_buf_printf(&config, "PersistentKeepalive = %d\n", (int)peer->persistent_keepalive);
    }
    if (len) *len = config.len;
    result = sb_buf_detach(&config);
done:
    sb_buf_free(&config);
    sb_wireguard_peer_vec_free(&peers);
    sb_wireguard_peer_stats_vec_free(&current);
    sb_wireguard_options_free(&runtime);
    return result;
}

/* Moves *src into *dst (dst's previous contents are released). */
static void take_peer(sb_wireguard_peer *dst, sb_wireguard_peer *src) {
    sb_wireguard_peer_free(dst);
    *dst = *src;
    memset(src, 0, sizeof *src);
}

int sb_wireguard_provision_host(sb_wireguard *wg, const sb_host *host, bool set_default_clash,
                                sb_host *out, sb_err *err) {
    int rc = -1;
    bool have_runtime = false;
    sb_wireguard_options runtime;
    sb_wireguard_peer_vec existing = {0};
    sb_wireguard_peer peer, candidate;
    sb_wireguard_peer_init(&peer);
    sb_wireguard_peer_init(&candidate);
    sb_wireguard_keypair keys = {0};
    char *allocated = NULL;
    sb_host updated;
    sb_host_init(&updated);

    if (sb_store_list_wireguard_peers(wg->store, &existing, err) != 0) goto done;
    sb_wireguard_peer *found = find_host_peer(&existing, host->id);
    if (found) {
        take_peer(&peer, found);
    } else {
        if (sb_wireguard_runtime_options(wg, &runtime, err) != 0) goto done;
        have_runtime = true;
        /* A device may already have a standalone WireGuard identity created
         * before unified enrollment existed. Reuse an exact-name, unlinked
         * peer instead of silently allocating a second address and keypair. */
        for (size_t i = 0; i < existing.len && !found; ++i)
            if (!existing.items[i].host_id && existing.items[i].name_len == host->name_len &&
                memcmp(S(existing.items[i].name), S(host->name), host->name_len) == 0)
                found = &existing.items[i];
        if (found) {
            take_peer(&candidate, found);
            sb_str_set(&candidate.host_id, S(host->id));
            free(candidate.allowed_ips);
            candidate.allowed_ips = subnet_cidr(S(runtime.address));
            candidate.enabled = true;
            if (sb_store_update_wireguard_peer(wg->store, &candidate, &peer, err) != 0) goto done;
        } else {
            if (sb_wireguard_generate_keypair(&keys, err) != 0) goto done;
            allocated = sb_store_next_wireguard_address(wg->store, S(runtime.address), err);
            if (!allocated) goto done;
            char *preshared = sb_wireguard_generate_preshared_key(err);
            if (!preshared) goto done;
            char *ip = peer_ip(allocated);
            sb_str_set(&candidate.id, "");
            free(candidate.name);
            candidate.name_len = 6 + host->name_len;
            candidate.name = sb_xmalloc(candidate.name_len + 1);
            memcpy(candidate.name, "host: ", 6);
            memcpy(candidate.name + 6, S(host->name), host->name_len);
            candidate.name[candidate.name_len] = '\0';
            sb_str_set(&candidate.private_key, keys.private_key);
            sb_str_set(&candidate.public_key, keys.public_key);
            free(candidate.preshared_key);
            candidate.preshared_key = preshared;
            free(candidate.address);
            candidate.address = sb_asprintf("%s/32", ip);
            free(ip);
            sb_str_set(&candidate.dns, "");
            candidate.enabled = true;
            candidate.persistent_keepalive = 25;
            free(candidate.allowed_ips);
            candidate.allowed_ips = subnet_cidr(S(runtime.address));
            candidate.quota_bytes = 0;
            sb_str_set(&candidate.host_id, S(host->id));
            if (sb_store_create_wireguard_peer(wg->store, &candidate, &peer, err) != 0) goto done;
        }
    }

    sb_host_copy(&updated, host);
    sb_str_set(&updated.wg_address, S(peer.address));
    updated.wg_address_len = updated.wg_address ? strlen(updated.wg_address) : 0;
    sb_str_set(&updated.wg_public_key, S(peer.public_key));
    updated.wg_public_key_len = updated.wg_public_key ? strlen(updated.wg_public_key) : 0;
    if (set_default_clash && !updated.clash_api) {
        char *ip = peer_ip(S(peer.address));
        updated.clash_api = sb_asprintf("http://%s:9090", ip);
        updated.clash_api_len = updated.clash_api ? strlen(updated.clash_api) : 0;
        free(ip);
    }
    rc = sb_store_update_host(wg->store, &updated, out, err);
done:
    sb_host_free(&updated);
    free(allocated);
    sb_wireguard_keypair_free(&keys);
    sb_wireguard_peer_free(&candidate);
    sb_wireguard_peer_free(&peer);
    sb_wireguard_peer_vec_free(&existing);
    if (have_runtime) sb_wireguard_options_free(&runtime);
    return rc;
}

int sb_wireguard_deprovision_host(sb_wireguard *wg, const char *host_id, sb_err *err) {
    sb_wireguard_peer_vec peers = {0};
    if (sb_store_list_wireguard_peers(wg->store, &peers, err) != 0) {
        sb_wireguard_peer_vec_free(&peers);
        return -1;
    }
    const sb_wireguard_peer *found = find_host_peer(&peers, host_id);
    int rc = 0;
    if (found) {
        sb_wireguard_remove_peer(wg, found->public_key);
        rc = sb_store_delete_wireguard_peer(wg->store, found->id, err);
    }
    sb_wireguard_peer_vec_free(&peers);
    return rc;
}

char *sb_wireguard_host_config(sb_wireguard *wg, const sb_host *host, sb_err *err) {
    return sb_wireguard_host_config_n(wg, host, NULL, err);
}

char *sb_wireguard_host_config_n(sb_wireguard *wg, const sb_host *host, size_t *len, sb_err *err) {
    if (len) *len = 0;
    sb_wireguard_peer_vec peers = {0};
    sb_host_vec hosts = {0};
    sb_wireguard_options runtime;
    bool have_runtime = false;
    char *server_public = NULL, *result = NULL;
    sb_buf config = {0};

    if (sb_store_list_wireguard_peers(wg->store, &peers, err) != 0) goto done;
    const sb_wireguard_peer *found = find_host_peer(&peers, host->id);
    if (!found) {
        sb_fail(err, SB_ERR_NOT_FOUND, "Host has no WireGuard peer");
        goto done;
    }
    if (sb_wireguard_runtime_options(wg, &runtime, err) != 0) goto done;
    have_runtime = true;
    const char *label = S(found->name);
    size_t label_len = found->name_len;
    if (label_len >= 6 && memcmp(label, "host: ", 6) == 0) { label += 6; label_len -= 6; }
    sb_buf_puts(&config, "# sb-easy managed host: ");
    sb_buf_append(&config, label, label_len);
    sb_buf_puts(&config, "\n[Interface]\n");
    sb_buf_printf(&config, "PrivateKey = %s\n", S(found->private_key));
    sb_buf_printf(&config, "Address = %s\n", S(found->address));
    if (runtime.mtu > 0U) sb_buf_printf(&config, "MTU = %u\n", (unsigned)runtime.mtu);
    uint16_t port = 0;
    bool this_has_endpoint = endpoint_port(host->wg_endpoint, &port);
    if (this_has_endpoint) sb_buf_printf(&config, "ListenPort = %u\n", (unsigned)port);
    server_public = sb_wireguard_server_public_key(wg, err);
    if (!server_public) goto done;
    sb_buf_printf(&config, "\n# Hub (central server)\n[Peer]\nPublicKey = %s\n", server_public);
    if (!sb_str_empty(found->preshared_key))
        sb_buf_printf(&config, "PresharedKey = %s\n", found->preshared_key);
    char *subnet = subnet_cidr(S(runtime.address));
    sb_buf_printf(&config, "AllowedIPs = %s\n", subnet);
    free(subnet);
    sb_buf_printf(&config, "Endpoint = %s:%u\nPersistentKeepalive = 25\n",
                  S(runtime.external_hostname), (unsigned)runtime.port);

    if (sb_store_list_hosts(wg->store, &hosts, err) != 0) goto done;
    for (size_t i = 0; i < hosts.len; ++i) {
        const sb_host *other = &hosts.items[i];
        if (strcmp(S(other->id), S(host->id)) == 0 || !other->enabled || !other->wg_public_key ||
            !other->wg_address)
            continue;
        uint16_t other_port = 0;
        bool other_has_endpoint = endpoint_port(other->wg_endpoint, &other_port);
        if (!other_has_endpoint && !this_has_endpoint) continue;
        char *ip = peer_ip(other->wg_address);
        sb_buf_puts(&config, "\n# Mesh: ");
        sb_buf_append(&config, S(other->name), other->name_len);
        sb_buf_printf(&config, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", other->wg_public_key, ip);
        free(ip);
        if (other_has_endpoint) sb_buf_printf(&config, "Endpoint = %s\n", other->wg_endpoint);
        sb_buf_puts(&config, "PersistentKeepalive = 25\n");
    }
    if (len) *len = config.len;
    result = sb_buf_detach(&config);
done:
    sb_buf_free(&config);
    free(server_public);
    sb_host_vec_free(&hosts);
    sb_wireguard_peer_vec_free(&peers);
    if (have_runtime) sb_wireguard_options_free(&runtime);
    return result;
}

/* ======================================================================
 * Kernel interface
 * ====================================================================== */

/* std::filesystem::create_directories(path), failing with the libstdc++
 * filesystem_error text. An existing directory is fine. */
static int create_directories(const char *path, sb_err *err) {
    int error = 0;
    struct stat info;
    if (sb_str_empty(path)) {
        error = EINVAL;
    } else if (stat(path, &info) == 0) {
        if (S_ISDIR(info.st_mode)) return 0;
        error = ENOTDIR;
    } else if (errno != ENOENT && errno != ENOTDIR) {
        error = errno;
    } else if (sb_mkdirs(path, 0777) != 0) {
        error = errno;
    } else {
        return 0;
    }
    return sb_fail(err, SB_ERR_IO, "filesystem error: cannot create directories: %s [%s]",
                   strerror(error), S(path));
}

/* The shared head of startup() and sync(): write <config_directory>/
 * <interface>.conf atomically from server_config(). *path_out is malloc'd. */
static int write_server_config(sb_wireguard *wg, const sb_wireguard_options *runtime,
                               char **path_out, sb_err *err) {
    if (create_directories(runtime->config_directory, err) != 0) return -1;
    char *name = sb_asprintf("%s.conf", S(runtime->interface));
    /* std::filesystem::path::operator/ on POSIX. */
    char *path = sb_path_join(runtime->config_directory, name);
    free(name);
    size_t config_len = 0;
    char *config = sb_wireguard_server_config_n(wg, &config_len, err);
    if (!config) {
        free(path);
        return -1;
    }
    int rc = sb_atomic_replace_file(path, config, config_len, NULL, NULL, err);
    free(config);
    if (rc != 0) {
        free(path);
        return -1;
    }
    *path_out = path;
    return 0;
}

int sb_wireguard_sync(sb_wireguard *wg, sb_err *err) {
    if (!wg->options.enabled) return 0;
    sb_wireguard_options runtime;
    if (sb_wireguard_runtime_options(wg, &runtime, err) != 0) return -1;
    char *path = NULL;
    int rc = write_server_config(wg, &runtime, &path, err);
    if (rc == 0) {
        const char *syncconf[] = {"wg", "syncconf", runtime.interface, path, NULL};
        rc = run(syncconf, true, NULL, err);
    }
    free(path);
    sb_wireguard_options_free(&runtime);
    return rc;
}

int sb_wireguard_startup(sb_wireguard *wg, sb_err *err) {
    if (!wg->options.enabled) return 0;
    sb_wireguard_options runtime;
    if (sb_wireguard_runtime_options(wg, &runtime, err) != 0) return -1;
    int rc = -1, code = 0;
    char *path = NULL, *mtu = NULL, *subnet = NULL;
    if (write_server_config(wg, &runtime, &path, err) != 0) goto done;

    const char *show[] = {"ip", "link", "show", runtime.interface, NULL};
    if (run(show, false, &code, err) != 0) goto done;
    if (code == 0) {
        const char *syncconf[] = {"wg", "syncconf", runtime.interface, path, NULL};
        if (run(syncconf, true, NULL, err) != 0) goto done;
    } else {
        const char *add[] = {"ip", "link", "add", runtime.interface, "type", "wireguard", NULL};
        if (run(add, true, NULL, err) != 0) goto done;
        if (runtime.mtu > 0U) {
            mtu = sb_asprintf("%u", (unsigned)runtime.mtu);
            const char *set_mtu[] = {"ip", "link", "set", runtime.interface, "mtu", mtu, NULL};
            if (run(set_mtu, true, NULL, err) != 0) goto done;
        }
        const char *address[] = {"ip", "address", "add", runtime.address, "dev",
                                 runtime.interface, NULL};
        if (run(address, true, NULL, err) != 0) goto done;
        const char *up[] = {"ip", "link", "set", "up", runtime.interface, NULL};
        if (run(up, true, NULL, err) != 0) goto done;
        const char *setconf[] = {"wg", "setconf", runtime.interface, path, NULL};
        if (run(setconf, true, NULL, err) != 0) goto done;
    }

    const char *forward[] = {"sysctl", "-w", "net.ipv4.ip_forward=1", NULL};
    if (run(forward, false, NULL, err) != 0) goto done;
    subnet = subnet_cidr(S(runtime.address));
    const char *masquerade[] = {"iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet,
                                "-o", runtime.egress_interface, "-j", "MASQUERADE", NULL};
    if (run(masquerade, false, &code, err) != 0) goto done;
    if (code != 0) {
        masquerade[3] = "-A";
        if (run(masquerade, false, NULL, err) != 0) goto done;
    }
    static const char *const directions[] = {"-i", "-o"};
    for (size_t i = 0; i < 2U; ++i) {
        const char *check[] = {"iptables", "-C", "FORWARD", directions[i], runtime.interface,
                               "-j", "ACCEPT", NULL};
        if (run(check, false, &code, err) != 0) goto done;
        if (code != 0) {
            check[1] = "-A";
            if (run(check, false, NULL, err) != 0) goto done;
        }
    }
    rc = 0;
done:
    free(subnet);
    free(mtu);
    free(path);
    sb_wireguard_options_free(&runtime);
    return rc;
}

void sb_wireguard_shutdown(sb_wireguard *wg) {
    if (!wg || !wg->options.enabled) return;
    /* noexcept in C++: the first failure silently ends the teardown. */
    sb_wireguard_options runtime;
    if (sb_wireguard_runtime_options(wg, &runtime, NULL) != 0) return;
    char *subnet = subnet_cidr(S(runtime.address));
    const char *delete_masquerade[] = {"iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet,
                                       "-o", runtime.egress_interface, "-j", "MASQUERADE", NULL};
    bool ok = run(delete_masquerade, false, NULL, NULL) == 0;
    static const char *const directions[] = {"-i", "-o"};
    for (size_t i = 0; ok && i < 2U; ++i) {
        const char *delete_forward[] = {"iptables", "-D", "FORWARD", directions[i],
                                        runtime.interface, "-j", "ACCEPT", NULL};
        ok = run(delete_forward, false, NULL, NULL) == 0;
    }
    if (ok) {
        const char *delete_link[] = {"ip", "link", "delete", runtime.interface, NULL};
        (void)run(delete_link, false, NULL, NULL);
    }
    free(subnet);
    sb_wireguard_options_free(&runtime);
}

void sb_wireguard_remove_peer(sb_wireguard *wg, const char *public_key) {
    if (!wg || !wg->options.enabled) return;
    sb_wireguard_options runtime;
    if (sb_wireguard_runtime_options(wg, &runtime, NULL) != 0) return;
    const char *remove_argv[] = {"wg", "set", runtime.interface, "peer", S(public_key), "remove",
                                 NULL};
    (void)run(remove_argv, false, NULL, NULL);
    sb_wireguard_options_free(&runtime);
}
