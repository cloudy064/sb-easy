#ifndef SBW_SUBSCRIPTIONS_H
#define SBW_SUBSCRIPTIONS_H
#include "../common.h"
sbj *sbw_subscriptions_summary(const sbj *source, const sbj *identity);
int sbw_subscriptions_merge(sbj *config, const sbj *identity, sbw_error *error);
sbj *sbw_subscriptions_change(const sbj *identity, const sbj *params, bool remove, sbw_error *error);
sbj *sbw_subscription_fetch(const char *url, HANDLE cancel, sbw_error *error);
#endif
