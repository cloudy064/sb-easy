#include "sb/json.h"
#include "test.h"

static char *roundtrip(const char *in, int indent) {
    sbj *v = sbj_parse_cstr(in);
    if (!v) return NULL;
    char *out = sbj_dump(v, indent);
    sbj_free(v);
    return out;
}

#define RT(in, indent, expected)                   \
    do {                                           \
        char *o = roundtrip(in, indent);           \
        CHECK_STR(o, expected);                    \
        free(o);                                   \
    } while (0)

TEST(sorted_compact) { RT("{\"b\":1,\"a\":[true,null,\"x\"]}", -1, "{\"a\":[true,null,\"x\"],\"b\":1}"); }

TEST(pretty_matches_nlohmann) {
    RT("{\"b\":{},\"a\":[1,{\"z\":[]}]}", 2,
       "{\n  \"a\": [\n    1,\n    {\n      \"z\": []\n    }\n  ],\n  \"b\": {}\n}");
}

TEST(floats_match_nlohmann) {
    RT("[1.0,0.5,100.25,1e20,1.5e-7,0.0001,123456789012345680000.0,-0.0,3.14159,1e15,1e16]", -1,
       "[1.0,0.5,100.25,1e+20,1.5e-07,0.0001,1.2345678901234568e+20,-0.0,3.14159,1e+15,1e+16]");
}

TEST(integers) {
    RT("[0,-1,9223372036854775807,-9223372036854775808,18446744073709551615]", -1,
       "[0,-1,9223372036854775807,-9223372036854775808,18446744073709551615]");
}

TEST(string_escapes) {
    RT("\"a\\u0001\\\"\\\\\\/\\n\\u00e9\\ud83d\\ude00\"", -1, "\"a\\u0001\\\"\\\\/\\n\xc3\xa9\xf0\x9f\x98\x80\"");
}

TEST(duplicate_keys_last_wins) { RT("{\"a\":1,\"a\":2}", -1, "{\"a\":2}"); }

TEST(embedded_nul_keys_are_distinct_and_round_trip) {
    sbj *value = sbj_parse_cstr("{\"password\\u0000extra\":2,\"z\":3}");
    REQUIRE(value);
    CHECK(sbj_get(value, "password") == NULL);
    sbj_set_int(value, "password", 1);
    CHECK_EQ_INT(sbj_as_int(sbj_getn(value, "password\0extra", 14), -1), 2);
    sbj *updated = sbj_object();
    sbj_update(updated, value);
    CHECK(sbj_equal(updated, value));
    sbj_free(updated);
    char *text = sbj_dump(value, -1);
    CHECK_STR(text, "{\"password\":1,\"password\\u0000extra\":2,\"z\":3}");
    free(text);
    sbj *copy = sbj_clone(value);
    CHECK(sbj_equal(value, copy));
    CHECK(sbj_del(copy, "password"));
    CHECK(sbj_get(copy, "password") == NULL);
    CHECK_EQ_INT(sbj_as_int(sbj_getn(copy, "password\0extra", 14), -1), 2);
    text = sbj_dump(copy, -1);
    CHECK_STR(text, "{\"password\\u0000extra\":2,\"z\":3}");
    free(text);
    sbj_free(copy);
    sbj_free(value);
}

TEST(rejects_invalid) {
    const char *bad[] = {"", "{", "[1,]", "{\"a\"}", "01", "1.", "\"\\x\"", "tru", "[1] x", "\"\xff\"", NULL};
    for (int i = 0; bad[i]; ++i) {
        sbj *v = sbj_parse_cstr(bad[i]);
        if (v) SB_FAIL_AT("accepted invalid input %s", bad[i]);
        sbj_free(v);
    }
}

TEST(object_ops) {
    sbj *o = sbj_object();
    sbj_set_str(o, "z", "1");
    sbj_set_int(o, "a", 2);
    sbj_set(o, "m", sbj_array());
    sbj_arr_push(sbj_get(o, "m"), sbj_bool(true));
    CHECK(sbj_del(o, "z"));
    CHECK(!sbj_has(o, "z"));
    CHECK_EQ_INT(sbj_get_int(o, "a", 0), 2);
    char *s = sbj_dump(o, -1);
    CHECK_STR(s, "{\"a\":2,\"m\":[true]}");
    free(s);
    sbj *c = sbj_clone(o);
    CHECK(sbj_equal(o, c));
    sbj_set_float(c, "a", 2.0);
    CHECK(sbj_equal(o, c)); /* 2 == 2.0 like nlohmann */
    sbj_free(c);
    sbj_free(o);
}
