#ifndef SBW_UPDATER_H
#define SBW_UPDATER_H
#include "release_trust.h"

typedef struct sbw_updater sbw_updater;
/* Only the installed LocalSystem service enables installation. Console and
 * development builds return an explanatory, read-only unavailable status. */
sbw_updater *sbw_updater_new(const wchar_t *install_directory, const wchar_t *data_directory,
    bool installed_service, sbw_error *error);
void sbw_updater_free(sbw_updater *updater);
sbj *sbw_updater_status(sbw_updater *updater);
int sbw_updater_check(sbw_updater *updater, const char *manifest_url, sbw_error *error);
int sbw_updater_download(sbw_updater *updater, const char *release_id, sbw_error *error);
int sbw_updater_install(sbw_updater *updater, const char *release_id, bool resume_connected, sbw_error *error);
int sbw_updater_cancel(sbw_updater *updater, sbw_error *error);
int sbw_updater_recover(sbw_updater *updater, sbw_error *error);
bool sbw_updater_installing(sbw_updater *updater);
int sbw_updater_health_parameters(sbw_updater *updater, const char *nonce, bool rollback, bool *resume_connected, sbw_error *error);
int sbw_updater_health_record(sbw_updater *updater, bool rollback, sbw_error *error);

/* Service-side post-upgrade health action is called by Windows Installer before
 * committing its transaction. The helper runs independently of installed files. */
int sbw_update_health_check(void);
int sbw_update_helper_main(int argc, wchar_t **argv);
#endif
