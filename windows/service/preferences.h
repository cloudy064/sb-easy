#ifndef SBW_PREFERENCES_H
#define SBW_PREFERENCES_H
#include "../common.h"

/* Passwords are UTF-8, 12–1024 bytes, never persisted. Envelopes follow
 * docs/preferences-format.md. Returned plaintext is private credential data. */
sbj *sbw_preferences_encrypt(const sbj *payload, const char *password, sbw_error *error);
sbj *sbw_preferences_decrypt(const sbj *envelope, const char *password, sbw_error *error);
bool sbw_preferences_envelope_valid(const sbj *envelope);
/* Export only roaming fields. Enrollment, device routes/process groups,
 * auto-connect, kill switch, capture/MITM and all CA material are excluded. */
sbj *sbw_preferences_payload(const sbj *identity, sbw_error *error);
sbj *sbw_preferences_merge(const sbj *identity, const sbj *payload, sbw_error *error);
sbj *sbw_preferences_preview(const sbj *identity);
#endif
