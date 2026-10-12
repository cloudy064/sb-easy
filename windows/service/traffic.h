#ifndef SBW_TRAFFIC_H
#define SBW_TRAFFIC_H
#include "../common.h"
/* Serialized by controller mutation_lock. Bounded detail, stable checkpoints. */
typedef struct sbw_traffic sbw_traffic;
bool sbw_traffic_running(sbw_traffic *traffic);
sbw_traffic *sbw_traffic_new(void);
void sbw_traffic_free(sbw_traffic *traffic);
void sbw_traffic_record(sbw_traffic *traffic, const sbj *snapshot, DWORD pid);
void sbw_traffic_new_core(sbw_traffic *traffic);
void sbw_traffic_clear(sbw_traffic *traffic);
sbj *sbw_traffic_snapshot(const sbw_traffic *traffic);
bool sbw_traffic_restore(sbw_traffic *traffic, const sbj *saved);
#endif
