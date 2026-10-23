#ifndef SBW_RELEASE_TRUST_H
#define SBW_RELEASE_TRUST_H
#include "../common.h"

#define SBW_RELEASE_MANIFEST_LIMIT (64U * 1024U)
#define SBW_RELEASE_SIGNATURE_LIMIT (256U * 1024U)
#define SBW_RELEASE_PACKAGE_LIMIT (512ULL * 1024ULL * 1024ULL)
#ifndef SB_EASY_PUBLISHER_THUMBPRINT
#define SB_EASY_PUBLISHER_THUMBPRINT ""
#endif

typedef struct sbw_release {
    char version[32], core_version[32], minimum_app_version[32];
    char installer[160], sha256[65], id[65];
    uint64_t bytes;
    unsigned rollout_percent;
} sbw_release;

/* Parsing is deliberately separate for regression tests. Production callers
 * must verify the detached signature before interpreting any manifest fields. */
int sbw_release_parse(const char *manifest, size_t length, const char *publisher,
    sbw_release *out, sbw_error *error);
bool sbw_release_version(const char *text, unsigned parts[3]);
int sbw_release_compare(const char *first, const char *second);
int sbw_release_eligible(const sbw_release *release, const char *current, unsigned cohort, sbw_error *error);
int sbw_release_verify_manifest(const void *manifest, size_t length, const void *signature,
    size_t signature_length, const char *publisher, sbw_release *out, sbw_error *error);
/* The caller pins the regular file open without write/delete sharing until its
 * use has finished. Both digest and Authenticode are checked against that file. */
int sbw_release_verify_file(const wchar_t *path, HANDLE file, const char *publisher,
    bool timestamp_required, sbw_error *error);
int sbw_release_verify_installer(const wchar_t *path, HANDLE file, const char *publisher,
    const sbw_release *release, sbw_error *error);
int sbw_release_hash(const void *data, size_t length, char output[65], sbw_error *error);
int sbw_release_hash_file(HANDLE file, uint64_t expected_size, const char *expected_hash,
    sbw_error *error);
#endif
