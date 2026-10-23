#include "desktop.h"
#include <glib-unix.h>
#include <polkit/polkit.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define SERVICE_NAME "io.sbeasy.Desktop.Tunnel"
typedef struct {
    GDBusConnection* bus;
    GMainLoop* loop;
    GThreadPool* workers;
    GMutex lock;
    GCancellable* authorization;
    sbl_runtime runtime;
    char *owner, *pending;
    uid_t owner_uid;
    bool cancelled, busy, test, closing, stop_queued;
    unsigned queued;
} service;
typedef struct {
    service* service;
    GDBusMethodInvocation* invocation;
    char *sender, *method, *a, *b;
    bool internal;
} request;
static const char introspection[] =
    "<node><interface name='" SBL_BUS_IFACE "'>"
    "<method name='Start'><arg type='s' name='profile' direction='in'/><arg type='s' "
    "name='status' direction='out'/></method>"
    "<method name='Stop'/><method name='Status'><arg type='s' name='status' "
    "direction='out'/></method>"
    "<method name='Select'><arg type='s' name='group' direction='in'/><arg type='s' "
    "name='node' direction='in'/><arg type='s' name='result' direction='out'/></method>"
    "<method name='Delay'><arg type='s' name='node' direction='in'/><arg type='s' "
    "name='result' direction='out'/></method>"
    "<method name='Probe'><arg type='s' name='url' direction='in'/><arg type='s' "
    "name='result' direction='out'/></method>"
    "</interface></node>";
static bool caller_uid(service* s, const char* sender, uid_t* uid) {
    GVariant* reply = g_dbus_connection_call_sync(
        s->bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
        "GetConnectionUnixUser", g_variant_new("(s)", sender), G_VARIANT_TYPE("(u)"),
        G_DBUS_CALL_FLAGS_NONE, 5000, NULL, NULL);
    if (!reply)
        return false;
    guint32 value;
    g_variant_get(reply, "(u)", &value);
    g_variant_unref(reply);
    *uid = (uid_t)value;
    return true;
}
static bool authorized(service* s, const char* sender, uid_t* uid) {
    if (!caller_uid(s, sender, uid) || *uid == 0)
        return false;
    if (s->test)
        return *uid == getuid();
    g_mutex_lock(&s->lock);
    GCancellable* cancel = s->authorization ? g_object_ref(s->authorization) : NULL;
    g_mutex_unlock(&s->lock);
    PolkitAuthority* authority = polkit_authority_get_sync(cancel, NULL);
    if (!authority) {
        g_clear_object(&cancel);
        return false;
    }
    PolkitSubject* subject = polkit_system_bus_name_new(sender);
    PolkitAuthorizationResult* result = polkit_authority_check_authorization_sync(
        authority, subject, "io.sbeasy.Desktop.tunnel", NULL,
        POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION, cancel, NULL);
    bool ok = result && polkit_authorization_result_get_is_authorized(result);
    if (result)
        g_object_unref(result);
    g_object_unref(subject);
    g_object_unref(authority);
    g_clear_object(&cancel);
    return ok;
}
static bool request_cancelled(request* r) {
    service* s = r->service;
    g_mutex_lock(&s->lock);
    bool cancelled = s->cancelled || s->closing;
    g_mutex_unlock(&s->lock);
    uid_t current;
    return cancelled || !caller_uid(s, r->sender, &current);
}
static void worker(void* data, void* user) {
    request* r = data;
    service* s = r->service;
    sb_err err = {0};
    sbj* result = NULL;
    bool ok = true;
    if (r->internal || !strcmp(r->method, "Stop")) {
        sbl_runtime_stop(&s->runtime);
        g_mutex_lock(&s->lock);
        g_clear_pointer(&s->owner, g_free);
        s->owner_uid = 0;
        g_mutex_unlock(&s->lock);
    } else if (!strcmp(r->method, "Start")) {
        uid_t uid = 0;
        if (!authorized(s, r->sender, &uid)) {
            sb_fail(&err, SB_ERR_VALIDATION,
                    "Administrator authorization was denied or the caller disappeared");
            ok = false;
        }
        sbj* profile = ok ? sbl_parse(r->a, 2u * 1024u * 1024u, &err) : NULL;
        if (ok && (!profile || request_cancelled(r))) {
            sb_fail(&err, SB_ERR_CONFLICT, "Tunnel start was cancelled");
            ok = false;
        }
        if (ok && sbl_runtime_start(&s->runtime, profile, !s->test, uid, &err))
            ok = false;
        sbj_free(profile);
        if (ok && request_cancelled(r)) {
            sbl_runtime_stop(&s->runtime);
            sb_fail(&err, SB_ERR_CONFLICT, "Tunnel owner disconnected during startup");
            ok = false;
        }
        if (ok) {
            g_mutex_lock(&s->lock);
            g_free(s->owner);
            s->owner = g_strdup(r->sender);
            s->owner_uid = uid;
            g_mutex_unlock(&s->lock);
            result = sbl_runtime_status(&s->runtime, &err);
        }
    } else if (!strcmp(r->method, "Status"))
        result = sbl_runtime_status(&s->runtime, &err);
    else if (!strcmp(r->method, "Select"))
        result = sbl_runtime_select(&s->runtime, r->a, r->b, &err);
    else if (!strcmp(r->method, "Delay"))
        result = sbl_runtime_delay(&s->runtime, r->a, &err);
    else if (!strcmp(r->method, "Probe"))
        result = sbl_runtime_probe(&s->runtime, r->a, &err);
    else {
        sb_fail(&err, SB_ERR_VALIDATION, "Unsupported tunnel operation");
        ok = false;
    }
    if (err.msg[0])
        ok = false;
    g_mutex_lock(&s->lock);
    if (!strcmp(r->method, "Start")) {
        g_clear_pointer(&s->pending, g_free);
        g_clear_object(&s->authorization);
        s->cancelled = false;
    }
    if (s->queued)
        --s->queued;
    if (!strcmp(r->method, "Stop"))
        s->stop_queued = false;
    s->busy = s->queued != 0;
    g_mutex_unlock(&s->lock);
    if (r->invocation) {
        if (!ok)
            g_dbus_method_invocation_return_dbus_error(
                r->invocation, "io.sbeasy.Desktop.Error",
                err.msg[0] ? err.msg : "Tunnel operation failed");
        else if (!strcmp(r->method, "Stop"))
            g_dbus_method_invocation_return_value(r->invocation, g_variant_new("()"));
        else {
            char* raw = sbj_dump(result, -1);
            g_dbus_method_invocation_return_value(r->invocation,
                                                  g_variant_new("(s)", raw));
            free(raw);
        }
        g_object_unref(r->invocation);
    }
    sbj_free(result);
    g_free(r->sender);
    g_free(r->method);
    g_free(r->a);
    g_free(r->b);
    g_free(r);
    (void)user;
}
static void queue_stop(service* s) {
    g_mutex_lock(&s->lock);
    if (s->stop_queued) {
        g_mutex_unlock(&s->lock);
        return;
    }
    s->stop_queued = true;
    ++s->queued;
    s->busy = true;
    g_mutex_unlock(&s->lock);
    request* r = g_new0(request, 1);
    r->service = s;
    r->internal = true;
    r->method = g_strdup("Stop");
    g_thread_pool_push(s->workers, r, NULL);
}
static void method(GDBusConnection* connection, const char* sender, const char* path,
                   const char* interface, const char* name, GVariant* parameters,
                   GDBusMethodInvocation* invocation, void* data) {
    service* s = data;
    const char *a = "", *b = "";
    if (!strcmp(name, "Start") || !strcmp(name, "Delay") || !strcmp(name, "Probe"))
        g_variant_get(parameters, "(&s)", &a);
    else if (!strcmp(name, "Select"))
        g_variant_get(parameters, "(&s&s)", &a, &b);
    if (strlen(a) > (!strcmp(name, "Start") ? 2u * 1024u * 1024u : 4096u) ||
        strlen(b) > 512) {
        g_dbus_method_invocation_return_dbus_error(
            invocation, "io.sbeasy.Desktop.Error", "Request exceeds the size limit");
        return;
    }
    bool start = !strcmp(name, "Start"), stop = !strcmp(name, "Stop");
    g_mutex_lock(&s->lock);
    bool own = s->owner && !strcmp(s->owner, sender),
         pending = s->pending && !strcmp(s->pending, sender);
    const char* reason = NULL;
    if (s->closing)
        reason = "Tunnel service is shutting down";
    else if ((s->owner && !own) || (!start && !own && !pending))
        reason = "This connection does not own the tunnel";
    else if (s->busy && !(stop && (own || pending) && !s->stop_queued))
        reason = "Another tunnel operation is in progress";
    if (!reason) {
        if (start) {
            s->pending = g_strdup(sender);
            s->authorization = g_cancellable_new();
            s->cancelled = false;
        }
        if (stop) {
            s->cancelled = true;
            if (s->authorization)
                g_cancellable_cancel(s->authorization);
            s->stop_queued = true;
        }
        ++s->queued;
        s->busy = true;
    }
    g_mutex_unlock(&s->lock);
    if (reason) {
        g_dbus_method_invocation_return_dbus_error(invocation,
                                                   "io.sbeasy.Desktop.Error", reason);
        return;
    }
    if (stop)
        sbl_runtime_cancel_start();
    request* r = g_new0(request, 1);
    r->service = s;
    r->invocation = g_object_ref(invocation);
    r->sender = g_strdup(sender);
    r->method = g_strdup(name);
    r->a = g_strdup(a);
    r->b = g_strdup(b);
    g_thread_pool_push(s->workers, r, NULL);
    (void)connection;
    (void)path;
    (void)interface;
}
static void owner_changed(GDBusConnection* connection, const char* sender,
                          const char* path, const char* interface, const char* signal,
                          GVariant* parameters, void* data) {
    service* s = data;
    const char *name, *old_owner, *new_owner;
    g_variant_get(parameters, "(&s&s&s)", &name, &old_owner, &new_owner);
    if (!*old_owner || *new_owner)
        return;
    g_mutex_lock(&s->lock);
    bool ours = (s->owner && !strcmp(s->owner, name)) ||
                (s->pending && !strcmp(s->pending, name));
    if (ours) {
        s->cancelled = true;
        if (s->authorization)
            g_cancellable_cancel(s->authorization);
        s->busy = true;
    }
    g_mutex_unlock(&s->lock);
    if (ours) {
        sbl_runtime_cancel_start();
        queue_stop(s);
    }
    (void)connection;
    (void)sender;
    (void)path;
    (void)interface;
    (void)signal;
}
static gboolean terminate_service(void* data) {
    service* s = data;
    g_mutex_lock(&s->lock);
    s->closing = true;
    s->cancelled = true;
    if (s->authorization)
        g_cancellable_cancel(s->authorization);
    g_mutex_unlock(&s->lock);
    sbl_runtime_cancel_start();
    g_main_loop_quit(s->loop);
    return G_SOURCE_REMOVE;
}
static void name_lost(GDBusConnection* connection, const char* name, void* data) {
    terminate_service(data);
    (void)connection;
    (void)name;
}
int main(int argc, char** argv) {
    umask(0077);
    service s = {0};
    const char* directory = "/run/sb-easy-desktop";
    if (argc == 3 && !strcmp(argv[1], "--session-test")) {
        if (!geteuid()) {
            fputs("Session test mode must never run as root\n", stderr);
            return 2;
        }
        s.test = true;
        directory = argv[2];
    } else if (argc != 1 || geteuid() != 0) {
        fputs("Run the installed tunnel service through systemd\n", stderr);
        return 2;
    }
    sb_err err = {0};
    if (sbl_runtime_init(&s.runtime, directory, &err)) {
        fprintf(stderr, "%s\n", err.msg);
        return 1;
    }
    g_mutex_init(&s.lock);
    s.loop = g_main_loop_new(NULL, FALSE);
    s.workers = g_thread_pool_new(worker, NULL, 1, TRUE, NULL);
    s.bus = g_bus_get_sync(s.test ? G_BUS_TYPE_SESSION : G_BUS_TYPE_SYSTEM, NULL, NULL);
    if (!s.bus || !s.workers) {
        fputs("Cannot open tunnel service bus\n", stderr);
        return 1;
    }
    GDBusNodeInfo* info = g_dbus_node_info_new_for_xml(introspection, NULL);
    const GDBusInterfaceVTable vtable = {.method_call = method};
    guint registration = g_dbus_connection_register_object(
        s.bus, SBL_BUS_PATH, info->interfaces[0], &vtable, &s, NULL, NULL);
    if (!registration) {
        fputs("Cannot register tunnel service\n", stderr);
        return 1;
    }
    guint subscription = g_dbus_connection_signal_subscribe(
        s.bus, "org.freedesktop.DBus", "org.freedesktop.DBus", "NameOwnerChanged",
        "/org/freedesktop/DBus", NULL, G_DBUS_SIGNAL_FLAGS_NONE, owner_changed, &s,
        NULL);
    guint name = g_bus_own_name_on_connection(
        s.bus, SERVICE_NAME, G_BUS_NAME_OWNER_FLAGS_NONE, NULL, name_lost, &s, NULL);
    g_unix_signal_add(SIGTERM, terminate_service, &s);
    g_unix_signal_add(SIGINT, terminate_service, &s);
    g_main_loop_run(s.loop);
    g_dbus_connection_signal_unsubscribe(s.bus, subscription);
    g_dbus_connection_unregister_object(s.bus, registration);
    g_bus_unown_name(name);
    g_thread_pool_free(s.workers, FALSE, TRUE);
    sbl_runtime_clear(&s.runtime);
    g_dbus_node_info_unref(info);
    g_object_unref(s.bus);
    g_main_loop_unref(s.loop);
    g_free(s.owner);
    g_free(s.pending);
    g_clear_object(&s.authorization);
    g_mutex_clear(&s.lock);
    return 0;
}
