#include "sb/util.h"
#include "test.h"

TEST(base64_roundtrip) {
    const char *in = "hello, world?>";
    char *e = sb_base64_encode((const unsigned char *)in, strlen(in));
    CHECK_STR(e, "aGVsbG8sIHdvcmxkPz4=");
    size_t n;
    unsigned char *d = sb_base64_decode(e, strlen(e), &n);
    CHECK_STR((char *)d, in);
    free(d);
    char *u = sb_base64url_encode((const unsigned char *)in, strlen(in));
    CHECK_STR(u, "aGVsbG8sIHdvcmxkPz4");
    d = sb_base64url_decode_strict(u, strlen(u), &n);
    CHECK_STR((char *)d, in);
    free(d);
    CHECK(sb_base64_decode_strict(u, strlen(u), &n) == NULL); /* missing padding */
    free(e);
    free(u);
}

TEST(uuid_shape) {
    char *u = sb_uuid_v4();
    CHECK_EQ_INT(strlen(u), 36);
    CHECK(u[14] == '4');
    free(u);
}

TEST(datetime) {
    int64_t t;
    CHECK(sb_parse_datetime("2026-01-02 03:04:05", &t) == 0);
    char *s = sb_sqlite_datetime(t);
    CHECK_STR(s, "2026-01-02 03:04:05");
    free(s);
    CHECK(sb_parse_datetime("2026-01-02T05:04:05+02:00", &t) == 0);
    s = sb_rfc3339(t);
    CHECK_STR(s, "2026-01-02T03:04:05Z");
    free(s);
}

TEST(split_join) {
    sb_strvec v = sb_split("a,,b", ',');
    CHECK_EQ_INT(v.len, 3);
    char *j = sb_join(&v, "|");
    CHECK_STR(j, "a||b");
    free(j);
    sb_strvec_free(&v);
}

TEST(hex_value) {
    CHECK_EQ_INT(sb_hex_value('0'), 0);
    CHECK_EQ_INT(sb_hex_value('9'), 9);
    CHECK_EQ_INT(sb_hex_value('a'), 10);
    CHECK_EQ_INT(sb_hex_value('F'), 15);
    CHECK_EQ_INT(sb_hex_value('g'), -1);
    CHECK_EQ_INT(sb_hex_value('/'), -1);
    CHECK_EQ_INT(sb_hex_value(' '), -1);
}

TEST(parse_int_range) {
    long v = -1;
    CHECK_EQ_INT(sb_parse_int_range("8080", 4, 1, 65535, &v), 0);
    CHECK_EQ_INT(v, 8080);
    CHECK_EQ_INT(sb_parse_int_range("65535", 5, 1, 65535, &v), 0);
    CHECK_EQ_INT(v, 65535);
    CHECK_EQ_INT(sb_parse_int_range("1", 1, 1, 65535, &v), 0);
    CHECK_EQ_INT(v, 1);
    v = 7;
    CHECK_EQ_INT(sb_parse_int_range("0", 1, 1, 65535, &v), -1);
    CHECK_EQ_INT(sb_parse_int_range("65536", 5, 1, 65535, &v), -1);
    CHECK_EQ_INT(sb_parse_int_range("abc", 3, 1, 65535, &v), -1);
    CHECK_EQ_INT(sb_parse_int_range("8080abc", 7, 1, 65535, &v), -1);
    CHECK_EQ_INT(sb_parse_int_range("", 0, 1, 65535, &v), -1);
    CHECK_EQ_INT(sb_parse_int_range(NULL, 0, 1, 65535, &v), -1);
    CHECK_EQ_INT(sb_parse_int_range("-5", 2, -10, 10, &v), -1);
    CHECK_EQ_INT(sb_parse_int_range(" 80", 3, 1, 65535, &v), -1);
    CHECK_EQ_INT(sb_parse_int_range("99999999999999999999", 20, 1, 65535, &v), -1);
    CHECK_EQ_INT(v, 7); /* untouched on failure */
    /* only len bytes are examined, so a longer buffer is fine */
    CHECK_EQ_INT(sb_parse_int_range("200 OK", 3, 100, 599, &v), 0);
    CHECK_EQ_INT(v, 200);
}
