#include "sb/agent_sync.h"
#include "sb/atomic_file.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SYNC_FILE_LIMIT (8u * 1024u * 1024u)
struct sb_agent_sync { char *path; sbj *document; };

bool sb_agent_sync_state_valid(const sbj *state) {
    return sbj_is_object(state) && sbj_is_integer(sbj_get(state, "base_version")) &&
        sbj_get_int(state, "base_version", -1) > 0 &&
        sbj_is_integer(sbj_get(state, "patch_version")) &&
        sbj_get_int(state, "patch_version", -1) >= 0 &&
        sbj_is_object(sbj_get(state, "base")) && sbj_is_object(sbj_get(state, "patch")) &&
        sbj_is_object(sbj_get(state, "config")) && sbj_is_object(sbj_get(state, "agent_settings"));
}
static bool request_valid(const sbj *request) {
    return sbj_is_object(request) && sbj_is_integer(sbj_get(request, "base_version")) &&
        sbj_get_int(request, "base_version", -1) > 0 &&
        sbj_is_integer(sbj_get(request, "patch_version")) &&
        sbj_get_int(request, "patch_version", -1) >= 0 &&
        sbj_is_object(sbj_get(request, "patch")) && sbj_is_object(sbj_get(request, "agent_settings"));
}
static bool same_versions(const sbj *a, const sbj *b) {
    return sbj_equal(sbj_get(a, "base_version"), sbj_get(b, "base_version")) &&
           sbj_equal(sbj_get(a, "patch_version"), sbj_get(b, "patch_version"));
}
static bool same_contents(const sbj *a, const sbj *b) {
    return sbj_equal(sbj_get(a, "patch"), sbj_get(b, "patch")) &&
           sbj_equal(sbj_get(a, "agent_settings"), sbj_get(b, "agent_settings"));
}
static sbj *request_from(const sbj *state) {
    sbj *result = sbj_object();
    const char *keys[] = {"base_version", "patch_version", "patch", "agent_settings"};
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; ++i)
        sbj_set(result, keys[i], sbj_clone(sbj_get(state, keys[i])));
    return result;
}
static int commit(sb_agent_sync *sync, sbj *document, sb_err *err) {
    int64_t version = sbj_get_int(sync->document, "local_version", 0);
    if (version == INT64_MAX) { sbj_free(document); return sb_fail(err, SB_ERR_CONFLICT, "Local configuration version exhausted"); }
    sbj_set_int(document, "local_version", version + 1);
    char *text = sbj_dump(document, -1);
    size_t length = strlen(text);
    int rc = length > SYNC_FILE_LIMIT ? sb_fail(err, SB_ERR_VALIDATION, "Configuration sync cache exceeds 8 MiB") :
        sb_atomic_replace_file(sync->path, text, length, NULL, NULL, err);
    free(text);
    if (rc) sbj_free(document);
    else { sbj_free(sync->document); sync->document = document; }
    return rc;
}
sb_agent_sync *sb_agent_sync_new(const char *path, const char *scope,
                                const sbj *legacy_settings, sb_err *err) {
    sbj *document = NULL;
    struct stat info;
    if (stat(path, &info) == 0) {
        if (!S_ISREG(info.st_mode) || info.st_size < 0 || (uint64_t)info.st_size > SYNC_FILE_LIMIT) {
            sb_fail(err, SB_ERR_VALIDATION, "Invalid configuration sync cache file"); return NULL;
        }
        size_t length = 0; char *text = sb_read_file(path, &length);
        if (text) document = sbj_parse(text, length, NULL, 0);
        free(text);
        const sbj *remote = sbj_get(document, "remote"), *pending = sbj_get(document, "pending");
        if (!sbj_is_object(document) || sbj_get_int(document, "format", 0) != 1 ||
            !sbj_string_is(sbj_get(document, "scope"), scope) ||
            !sbj_is_integer(sbj_get(document, "local_version")) || sbj_get_int(document, "local_version", -1) < 0 ||
            (!sbj_is_null(remote) && !sb_agent_sync_state_valid(remote)) ||
            (!sbj_is_null(pending) && !request_valid(pending))) {
            sbj_free(document); sb_fail(err, SB_ERR_VALIDATION, "Invalid or mismatched configuration sync cache"); return NULL;
        }
    } else if (errno != ENOENT) {
        sb_fail(err, SB_ERR_IO, "Cannot inspect configuration sync cache"); return NULL;
    } else {
        document = sbj_object(); sbj_set_int(document, "format", 1); sbj_set_str(document, "scope", scope);
        sbj_set_int(document, "local_version", 0); sbj_set_null(document, "remote"); sbj_set_null(document, "pending");
        sbj_set_bool(document, "conflict", false);
        if (legacy_settings && sbj_obj_len(legacy_settings)) sbj_set(document, "legacy_settings", sbj_clone(legacy_settings));
    }
    sb_agent_sync *sync = sb_xcalloc(1, sizeof *sync);
    sync->path = sb_strdup(path); sync->document = document;
    return sync;
}
void sb_agent_sync_free(sb_agent_sync *sync) {
    if (sync) { free(sync->path); sbj_free(sync->document); free(sync); }
}
sbj *sb_agent_sync_snapshot(const sb_agent_sync *sync) {
    const sbj *remote = sbj_get(sync->document, "remote"), *pending = sbj_get(sync->document, "pending");
    sbj *snapshot = sbj_is_object(remote) ? sbj_clone(remote) : sbj_object();
    if (!sbj_is_object(remote)) {
        sbj_set_int(snapshot, "base_version", 0); sbj_set_int(snapshot, "patch_version", 0);
        const char *keys[] = {"base", "patch", "config", "agent_settings"};
        for (size_t i = 0; i < sizeof keys / sizeof keys[0]; ++i) sbj_set(snapshot, keys[i], sbj_object());
    }
    sbj_set(snapshot, "server_patch", sbj_clone(sbj_get(snapshot, "patch")));
    sbj_set(snapshot, "server_agent_settings", sbj_clone(sbj_get(snapshot, "agent_settings")));
    if (sbj_is_object(pending)) {
        sbj_set(snapshot, "patch", sbj_clone(sbj_get(pending, "patch")));
        sbj_set(snapshot, "agent_settings", sbj_clone(sbj_get(pending, "agent_settings")));
        sbj_set(snapshot, "pending_base_version", sbj_clone(sbj_get(pending, "base_version")));
        sbj_set(snapshot, "pending_patch_version", sbj_clone(sbj_get(pending, "patch_version")));
    }
    sbj_set_bool(snapshot, "pending", sbj_is_object(pending));
    sbj_set_bool(snapshot, "conflict", sbj_get_bool(sync->document, "conflict", false));
    sbj_set_int(snapshot, "local_version", sbj_get_int(sync->document, "local_version", 0));
    return snapshot;
}
int sb_agent_sync_observe(sb_agent_sync *sync, const sbj *state, sb_err *err) {
    if (!sb_agent_sync_state_valid(state)) return sb_fail(err, SB_ERR_UPSTREAM, "Invalid server configuration state");
    const sbj *old = sbj_get(sync->document, "remote");
    if (sbj_equal(old, state)) return 0;
    sbj *next = sbj_clone(sync->document);
    sbj_set(next, "remote", sbj_clone(state));
    const sbj *legacy = sbj_get(next, "legacy_settings");
    bool initialized = sbj_has(state, "agent_settings_initialized") ?
        sbj_get_bool(state, "agent_settings_initialized", true) : sbj_get_int(state, "patch_version", 0) != 0;
    if (!sbj_is_object(old) && sbj_is_object(legacy) && !initialized) {
        sbj *pending = request_from(state); sbj_set(pending, "agent_settings", sbj_clone(legacy));
        sbj_set(next, "pending", pending);
    }
    sbj_del(next, "legacy_settings");
    const sbj *pending = sbj_get(next, "pending");
    if (sbj_is_object(pending) && same_contents(pending, state)) sbj_set_null(next, "pending");
    pending = sbj_get(next, "pending");
    sbj_set_bool(next, "conflict", sbj_is_object(pending) && !same_versions(pending, state));
    return commit(sync, next, err);
}
int sb_agent_sync_queue(sb_agent_sync *sync, const sbj *edit, sb_err *err) {
    const sbj *remote = sbj_get(sync->document, "remote");
    if (!sbj_is_object(remote)) return sb_fail(err, SB_ERR_CONFLICT, "Fetch the server configuration before editing");
    if (!sbj_is_object(edit) || !sbj_is_integer(sbj_get(edit, "local_version")) ||
        sbj_get_int(edit, "local_version", -1) != sbj_get_int(sync->document, "local_version", 0) || !same_versions(edit, remote))
        return sb_fail(err, SB_ERR_CONFLICT, "Configuration changed; reload and review before saving");
    const char *resolve = sbj_get_str(edit, "resolve", "");
    bool discard = strcmp(resolve, "use_server") == 0, retry = strcmp(resolve, "retry_local") == 0;
    if (*resolve && !discard && !retry) return sb_fail(err, SB_ERR_VALIDATION, "Invalid configuration conflict resolution");
    if (!discard && !request_valid(edit)) return sb_fail(err, SB_ERR_VALIDATION, "Configuration patch and agent_settings must be objects");
    if (sbj_get_bool(sync->document, "conflict", false) && !discard && !retry)
        return sb_fail(err, SB_ERR_CONFLICT, "Review both configurations and explicitly resolve the conflict");
    sbj *next = sbj_clone(sync->document);
    bool had_pending = sbj_is_object(sbj_get(sync->document, "pending"));
    bool conflicted = sbj_get_bool(sync->document, "conflict", false);
    /* A prior PUT may be in flight or have committed without a response.
     * Keep an explicit undo until the network loop reconciles it, even when
     * its desired content equals the last confirmed remote snapshot. */
    sbj *pending = discard ? (had_pending && !conflicted ? request_from(remote) : sbj_null()) :
        (same_contents(edit, remote) && !had_pending ? sbj_null() : request_from(edit));
    sbj_set(next, "pending", pending);
    sbj_set_bool(next, "conflict", false);
    return commit(sync, next, err);
}
sbj *sb_agent_sync_request(const sb_agent_sync *sync) {
    const sbj *pending = sbj_get(sync->document, "pending");
    return sbj_is_object(pending) && !sbj_get_bool(sync->document, "conflict", false) ? sbj_clone(pending) : NULL;
}
int sb_agent_sync_acknowledge(sb_agent_sync *sync, const sbj *sent, const sbj *state, sb_err *err) {
    if (!sb_agent_sync_state_valid(state) || !same_contents(sent, state))
        return sb_fail(err, SB_ERR_UPSTREAM, "Server did not acknowledge the submitted configuration");
    sbj *next = sbj_clone(sync->document);
    const sbj *pending = sbj_get(next, "pending");
    if (sbj_equal(pending, sent)) sbj_set_null(next, "pending");
    else if (sbj_is_object(pending) && same_versions(pending, sent)) {
        sbj *updated = sbj_clone(pending);
        sbj_set(updated, "base_version", sbj_clone(sbj_get(state, "base_version")));
        sbj_set(updated, "patch_version", sbj_clone(sbj_get(state, "patch_version")));
        sbj_set(next, "pending", updated);
    } else if (sbj_is_null(pending) && same_versions(sbj_get(next, "remote"), sent) &&
               !same_contents(sbj_get(next, "remote"), state)) {
        /* A user discarded/undid the in-flight edit. Its PUT may already
         * have committed; keep the undo as the next conditional request. */
        sbj *undo = request_from(sbj_get(next, "remote"));
        sbj_set(undo, "base_version", sbj_clone(sbj_get(state, "base_version")));
        sbj_set(undo, "patch_version", sbj_clone(sbj_get(state, "patch_version")));
        sbj_set(next, "pending", undo);
    }
    sbj_set(next, "remote", sbj_clone(state));
    pending = sbj_get(next, "pending");
    sbj_set_bool(next, "conflict", sbj_is_object(pending) && !same_versions(pending, state));
    return commit(sync, next, err);
}
