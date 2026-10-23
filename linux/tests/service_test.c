#include "desktop.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define REQUIRE(x)                                                                     \
    do {                                                                               \
        if (!(x)) {                                                                    \
            fprintf(stderr, "Service contract failed at %d: %s\n", __LINE__, #x);      \
            exit(1);                                                                   \
        }                                                                              \
    } while (0)
static GDBusConnection* connection(void) {
    return g_dbus_connection_new_for_address_sync(
        g_getenv("DBUS_SESSION_BUS_ADDRESS"),
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
            G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
        NULL, NULL, NULL);
}
static GVariant* call(GDBusConnection* bus, const char* method, GVariant* parameters) {
    return g_dbus_connection_call_sync(bus, "io.sbeasy.Desktop.Tunnel", SBL_BUS_PATH,
                                       SBL_BUS_IFACE, method, parameters, NULL,
                                       G_DBUS_CALL_FLAGS_NONE, 10000, NULL, NULL);
}
static sbj* decode(GVariant* reply) {
    REQUIRE(reply);
    const char* raw;
    g_variant_get(reply, "(&s)", &raw);
    sbj* out = sbl_parse(raw, SBL_MAX_STATE, NULL);
    g_variant_unref(reply);
    REQUIRE(out);
    return out;
}
int main(int argc, char** argv) {
    REQUIRE(argc == 3);
    REQUIRE(geteuid() != 0);
    GDBusConnection *owner = connection(), *other = connection();
    REQUIRE(owner && other);
    for (unsigned i = 0; i < 100; ++i) {
        GVariant* reply = g_dbus_connection_call_sync(
            owner, "org.freedesktop.DBus", "/org/freedesktop/DBus",
            "org.freedesktop.DBus", "NameHasOwner",
            g_variant_new("(s)", "io.sbeasy.Desktop.Tunnel"), G_VARIANT_TYPE("(b)"),
            G_DBUS_CALL_FLAGS_NONE, 1000, NULL, NULL);
        gboolean ready = FALSE;
        if (reply) {
            g_variant_get(reply, "(b)", &ready);
            g_variant_unref(reply);
        }
        if (ready)
            break;
        g_usleep(20000);
    }
    sbj* profile = sbl_new_profile("Service fixture");
    char* body = sb_asprintf("{\"outbounds\":[{\"type\":\"http\",\"tag\":\"Fixture\","
                             "\"server\":\"127.0.0.1\",\"server_port\":%s}]}",
                             argv[1]);
    REQUIRE(sbl_import(profile, "Fixture", "", body, NULL) == 0);
    free(body);
    char* raw = sbj_dump(profile, -1);
    sbj* status = decode(call(owner, "Start", g_variant_new("(s)", raw)));
    REQUIRE(sbj_get_bool(status, "running", false));
    REQUIRE(!sbj_get_bool(status, "tun", true));
    char* dump = sbj_dump(status, -1);
    REQUIRE(!strstr(dump, "password") && !strstr(dump, "secret"));
    free(dump);
    sbj_free(status);
    REQUIRE(!call(other, "Status", g_variant_new("()")));
    REQUIRE(!call(other, "Stop", g_variant_new("()")));
    REQUIRE(!call(other, "Start", g_variant_new("(s)", raw)));
    char* url = sb_asprintf("http://127.0.0.1:%s/slow", argv[2]);
    sbj* probe = decode(call(owner, "Probe", g_variant_new("(s)", url)));
    REQUIRE(sbj_get_bool(probe, "success", false) &&
            sbj_get_bool(probe, "route_observed", false));
    sbj_free(probe);
    REQUIRE(g_dbus_connection_close_sync(owner, NULL, NULL));
    g_object_unref(owner);
    GVariant* reply = NULL;
    for (unsigned i = 0; i < 100 && !reply; ++i) {
        g_usleep(20000);
        reply = call(other, "Start", g_variant_new("(s)", raw));
    }
    status = decode(reply);
    REQUIRE(sbj_get_bool(status, "running", false));
    sbj_free(status);
    reply = call(other, "Stop", g_variant_new("()"));
    REQUIRE(reply);
    g_variant_unref(reply);
    REQUIRE(!call(other, "Status", g_variant_new("()")));
    g_dbus_connection_close_sync(other, NULL, NULL);
    g_object_unref(other);
    sbj_free(profile);
    free(raw);
    free(url);
    puts("Private D-Bus ownership, real core and forced proxy contracts passed");
    return 0;
}
