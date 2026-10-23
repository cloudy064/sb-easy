#ifndef SBW_SUBSCRIPTIONS_H
#define SBW_SUBSCRIPTIONS_H
#include "../common.h"
sbj *sbw_subscriptions_summary(const sbj *source, const sbj *identity);
int sbw_subscriptions_merge(sbj *config, const sbj *identity, sbw_error *error);
sbj *sbw_subscriptions_change(const sbj *identity, const sbj *params, bool remove, sbw_error *error);
sbj *sbw_subscription_fetch(const char *url, HANDLE cancel, sbw_error *error);
/* Native import/report. Body and returned nodes are private credential data;
 * only the report and subscriptions_summary belong in the WebView response. */
sbj *sbw_subscription_parse(const char *body, size_t length, sbw_error *error);
bool sbw_subscription_node_valid(const sbj *node);
sbj *sbw_subscriptions_import(const sbj *identity, const sbj *params, HANDLE cancel, sbw_error *error);
sbj *sbw_subscriptions_refresh(const sbj *identity, const char *id, HANDLE cancel, sbw_error *error);
/* Failure bookkeeping never changes any saved nodes or URL. */
sbj *sbw_subscriptions_failure(const sbj *identity, const char *id, const char *code, uint64_t now);
/* Borrowed ID of one due remote subscription, NULL when none is due. */
const char *sbw_subscriptions_due(const sbj *identity, uint64_t now);
/* Strict Subscription-Userinfo parser; malformed/duplicate/overflow fields
 * produce available=false and a fixed warning, never invented zero usage. */
sbj *sbw_subscription_metadata(const char *header, uint64_t now);
#endif
