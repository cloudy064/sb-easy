/* Minimal test harness: TEST(name) { ... } plus CHECK/CHECK_STR/... macros.
 * Each test file includes this header once and defines tests; main() runs all. */
#ifndef SB_TEST_H
#define SB_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*sb_test_fn)(void);
static struct { const char *name; sb_test_fn fn; } sb_tests[512];
static int sb_test_count, sb_test_failures, sb_test_current_failed;

#define TEST(tname)                                                        \
    static void test_##tname(void);                                        \
    __attribute__((constructor)) static void register_##tname(void) {      \
        sb_tests[sb_test_count].name = #tname;                             \
        sb_tests[sb_test_count++].fn = test_##tname;                       \
    }                                                                     \
    static void test_##tname(void)

#define SB_FAIL_AT(...)                                                   \
    do {                                                                  \
        fprintf(stderr, "  %s:%d: ", __FILE__, __LINE__);                 \
        fprintf(stderr, __VA_ARGS__);                                     \
        fputc('\n', stderr);                                              \
        sb_test_current_failed = 1;                                       \
    } while (0)

#define CHECK(cond)                                                       \
    do { if (!(cond)) SB_FAIL_AT("CHECK(%s) failed", #cond); } while (0)
#define REQUIRE(cond)                                                     \
    do { if (!(cond)) { SB_FAIL_AT("REQUIRE(%s) failed", #cond); return; } } while (0)
#define CHECK_EQ_INT(a, b)                                                \
    do { long long _a = (long long)(a), _b = (long long)(b);              \
         if (_a != _b) SB_FAIL_AT("%s == %s: %lld != %lld", #a, #b, _a, _b); } while (0)
#define CHECK_STR(a, b)                                                   \
    do { const char *_a = (a), *_b = (b);                                 \
         if (!_a || !_b || strcmp(_a, _b) != 0)                           \
             SB_FAIL_AT("%s == %s:\n    got:      %s\n    expected: %s",  \
                        #a, #b, _a ? _a : "(null)", _b ? _b : "(null)"); } while (0)
#define CHECK_CONTAINS(hay, needle)                                       \
    do { const char *_h = (hay), *_n = (needle);                          \
         if (!_h || !strstr(_h, _n))                                      \
             SB_FAIL_AT("expected %s to contain \"%s\", got: %s", #hay, _n, _h ? _h : "(null)"); } while (0)

int main(int argc, char **argv) {
    for (int i = 0; i < sb_test_count; ++i) {
        if (argc > 1 && !strstr(sb_tests[i].name, argv[1])) continue;
        sb_test_current_failed = 0;
        sb_tests[i].fn();
        printf("%s %s\n", sb_test_current_failed ? "FAIL" : "ok  ", sb_tests[i].name);
        sb_test_failures += sb_test_current_failed;
    }
    printf("%d test(s), %d failure(s)\n", sb_test_count, sb_test_failures);
    return sb_test_failures ? 1 : 0;
}

#endif
