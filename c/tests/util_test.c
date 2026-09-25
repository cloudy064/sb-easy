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
