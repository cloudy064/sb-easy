#include "proxy_clock_internal.h"
#include "sb/proxy_users.h"
#include "sqlite_internal.h"
#include <limits.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define FENCE_MS INT64_C(60000)

typedef struct proxy_epoch_clock {
    char *user;
    int64_t epoch, until;
    struct proxy_epoch_clock *next;
} proxy_epoch_clock;

struct sb_proxy_clock {
    pthread_mutex_t mutex;
    dev_t device;
    ino_t inode;
    sqlite3 *memory_identity;
    pid_t process;
    size_t references;
    int64_t startup_until, last_now;
    bool used;
    sb_proxy_monotonic_fn now;
    void *now_context;
    proxy_epoch_clock *epochs;
    struct sb_proxy_clock *next;
};

static pthread_mutex_t registry_mutex = PTHREAD_MUTEX_INITIALIZER;
static sb_proxy_clock *registry;
static int64_t real_monotonic(void *unused) {
    (void)unused;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 ||
        now.tv_sec > (INT64_MAX - 999) / 1000 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000)
        return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static proxy_epoch_clock *epoch_find(sb_proxy_clock *clock, const char *user) {
    for (proxy_epoch_clock *entry = clock->epochs; entry; entry = entry->next)
        if (sb_streq(entry->user, user)) return entry;
    return NULL;
}
static proxy_epoch_clock *epoch_add(sb_proxy_clock *clock, const char *user, int64_t epoch, int64_t until) {
    proxy_epoch_clock *entry = sb_xcalloc(1, sizeof *entry);
    entry->user = sb_strdup(user); entry->epoch = epoch; entry->until = until;
    entry->next = clock->epochs; clock->epochs = entry;
    return entry;
}
static void destroy_clock(sb_proxy_clock *clock) {
    while (clock->epochs) {
        proxy_epoch_clock *entry = clock->epochs; clock->epochs = entry->next;
        free(entry->user); free(entry);
    }
    pthread_mutex_destroy(&clock->mutex); free(clock);
}
static bool same_identity(const sb_proxy_clock *left, const sb_proxy_clock *right) {
    if (left->process != right->process) return false;
    if (left->memory_identity || right->memory_identity)
        return left->memory_identity == right->memory_identity;
    return left->device == right->device && left->inode == right->inode;
}
static sb_proxy_clock *find_clock(const sb_proxy_clock *identity) {
    for (sb_proxy_clock *clock = registry; clock; clock = clock->next)
        if (same_identity(clock, identity)) return clock;
    return NULL;
}

/* A consistent read at open records which epochs already existed. If another
 * process resets after this snapshot, its changed epoch triggers a fresh fence
 * when this process first observes it. No foreign monotonic timestamp is used. */
static int initialize_snapshot(sb_proxy_clock *clock, sqlite3 *db, sb_err *err) {
    if (sbq_begin(db, err)) return -1;
    int row = -1;
    int64_t tables = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
            "AND name IN ('proxy_users','proxy_leases')", err);
        if (q.rc != 0) goto failed;
        row = sbq_step_row(q.st, err);
        tables = row == 1 ? sbq_int(q.st, 0) : -1;
    }
    if (tables < 0) goto failed;
    if (tables == 0) return sbq_commit(db, err); /* Fresh database, before migrations. */
    if (tables != 2) { sb_fail(err, SB_ERR_GENERIC, "Incomplete proxy lease schema"); goto failed; }
    bool outstanding = false;
    {
        SBQ_AUTO q = sbq_stmt_open(db, "SELECT EXISTS(SELECT 1 FROM proxy_leases WHERE grant_bytes>used_bytes)", err);
        if (q.rc != 0) goto failed;
        row = sbq_step_row(q.st, err);
        outstanding = row == 1 && sbq_int(q.st, 0) != 0;
    }
    if (row != 1) goto failed;
    {
        SBQ_AUTO q = sbq_stmt_open(db, "SELECT id,epoch FROM proxy_users WHERE deleted=0", err);
        if (q.rc != 0) goto failed;
        while ((row = sbq_step_row(q.st, err)) == 1) {
            const char *user = (const char *)sqlite3_column_text(q.st, 0);
            int64_t epoch = sbq_int(q.st, 1);
            if (!user || !*user || strlen(user) > 128 || epoch < 1) {
                sb_fail(err, SB_ERR_GENERIC, "Invalid persisted proxy epoch"); row = -1; break;
            }
            epoch_add(clock, user, epoch, epoch > 1 ? clock->last_now + FENCE_MS : 0);
        }
    }
    if (row < 0) goto failed;
    if (sbq_commit(db, err)) goto failed;
    int64_t observed = real_monotonic(NULL);
    if (observed < clock->last_now || observed > INT64_MAX - FENCE_MS)
        return sb_fail(err, SB_ERR_GENERIC, "Monotonic clock is unavailable");
    clock->last_now = observed;
    if (outstanding) clock->startup_until = observed + FENCE_MS;
    for (proxy_epoch_clock *entry = clock->epochs; entry; entry = entry->next)
        if (entry->epoch > 1) entry->until = observed + FENCE_MS;
    return 0;
failed:
    sbq_rollback(db); return -1;
}

sb_proxy_clock *sb_proxy_clock_attach(sqlite3 *handle, sb_err *err) {
    sb_proxy_clock identity = {0};
    identity.process = getpid();
    const char *filename = sqlite3_db_filename(handle, "main");
    struct stat status;
    if (filename && *filename && !stat(filename, &status)) {
        identity.device = status.st_dev; identity.inode = status.st_ino;
    } else identity.memory_identity = handle; /* :memory: is private per connection. */
    pthread_mutex_lock(&registry_mutex);
    sb_proxy_clock *shared = find_clock(&identity);
    if (shared) ++shared->references;
    pthread_mutex_unlock(&registry_mutex);
    if (shared) return shared;

    sb_proxy_clock *clock = sb_xcalloc(1, sizeof *clock);
    clock->device = identity.device; clock->inode = identity.inode;
    clock->memory_identity = identity.memory_identity; clock->process = identity.process;
    clock->references = 1; clock->now = real_monotonic; clock->last_now = real_monotonic(NULL);
    pthread_mutex_init(&clock->mutex, NULL);
    if (clock->last_now < 0 || clock->last_now > INT64_MAX - FENCE_MS) {
        sb_fail(err, SB_ERR_GENERIC, "Monotonic clock is unavailable"); destroy_clock(clock); return NULL;
    }
    if (initialize_snapshot(clock, handle, err)) { destroy_clock(clock); return NULL; }
    pthread_mutex_lock(&registry_mutex);
    shared = find_clock(&identity);
    if (shared) ++shared->references;
    else { clock->next = registry; registry = clock; }
    pthread_mutex_unlock(&registry_mutex);
    if (shared) { destroy_clock(clock); return shared; }
    return clock;
}
void sb_proxy_clock_detach(sb_proxy_clock *clock) {
    if (!clock) return;
    pthread_mutex_lock(&registry_mutex);
    if (--clock->references) { pthread_mutex_unlock(&registry_mutex); return; }
    sb_proxy_clock **cursor = &registry;
    while (*cursor && *cursor != clock) cursor = &(*cursor)->next;
    if (*cursor == clock) *cursor = clock->next;
    pthread_mutex_unlock(&registry_mutex);
    destroy_clock(clock);
}

static int64_t read_now(sb_proxy_clock *clock) {
    int64_t now = clock->now(clock->now_context);
    if (now < clock->last_now || now < 0 || now > INT64_MAX - FENCE_MS) return -1;
    clock->last_now = now; return now;
}
static proxy_epoch_clock *observe_epoch(sb_proxy_clock *clock, const char *user, int64_t epoch, int64_t now) {
    proxy_epoch_clock *entry = epoch_find(clock, user);
    if (!entry) entry = epoch_add(clock, user, epoch, epoch == 1 ? 0 : now + FENCE_MS);
    else if (entry->epoch != epoch) { entry->epoch = epoch; entry->until = now + FENCE_MS; }
    return entry;
}
int64_t sb_proxy_clock_wait_ms(sb_database *database, const char *user, int64_t epoch) {
    sb_proxy_clock *clock = sb_database_proxy_clock(database);
    if (!clock) return FENCE_MS;
    pthread_mutex_lock(&clock->mutex);
    clock->used = true;
    int64_t now = read_now(clock), remaining = FENCE_MS;
    if (now >= 0) {
        proxy_epoch_clock *entry = observe_epoch(clock, user, epoch, now);
        int64_t until = entry->until > clock->startup_until ? entry->until : clock->startup_until;
        remaining = until > now ? until - now : 0;
    }
    pthread_mutex_unlock(&clock->mutex);
    return remaining;
}
void sb_proxy_clock_reset_epoch(sb_database *database, const char *user, int64_t epoch) {
    sb_proxy_clock *clock = sb_database_proxy_clock(database);
    if (!clock) return;
    pthread_mutex_lock(&clock->mutex);
    clock->used = true;
    int64_t now = read_now(clock);
    if (now >= 0) {
        proxy_epoch_clock *entry = observe_epoch(clock, user, epoch, now);
        entry->until = now + FENCE_MS;
    }
    pthread_mutex_unlock(&clock->mutex);
}

/* Dependency-injection seam, never controlled by HTTP/settings. It can only
 * replace the clock before an epoch has been observed or a lease/reset used.
 * Startup fences are restarted, not shortened, in the supplied time domain. */
int sb_proxy_clock_set_source(sb_database *database, sb_proxy_monotonic_fn source, void *context, sb_err *err) {
    if (!database || !source) return sb_fail(err, SB_ERR_VALIDATION, "A monotonic clock source is required");
    sb_database_lock(database);
    sb_proxy_clock *clock = sb_database_proxy_clock(database);
    pthread_mutex_lock(&clock->mutex);
    int rc = -1;
    if (clock->used) sb_fail(err, SB_ERR_CONFLICT, "Proxy clock source is already in use");
    else {
        int64_t now = source(context);
        if (now < 0 || now > INT64_MAX - FENCE_MS) sb_fail(err, SB_ERR_VALIDATION, "Invalid monotonic clock source");
        else {
            clock->now = source; clock->now_context = context; clock->last_now = now;
            if (clock->startup_until) clock->startup_until = now + FENCE_MS;
            for (proxy_epoch_clock *entry = clock->epochs; entry; entry = entry->next)
                if (entry->until) entry->until = now + FENCE_MS;
            rc = 0;
        }
    }
    pthread_mutex_unlock(&clock->mutex); sb_database_unlock(database); return rc;
}
