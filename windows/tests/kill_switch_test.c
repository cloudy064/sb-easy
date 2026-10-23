#include <winsock2.h>
#include <ws2tcpip.h>
#include "../service/kill_switch_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(value)                                                                                         \
    do {                                                                                                     \
        if (!(value)) {                                                                                      \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #value);                                      \
            exit(1);                                                                                         \
        }                                                                                                    \
    } while (0)

typedef struct flow {
    unsigned layer;
    const char *application;
    UINT32 flags;
    UINT64 interface_luid;
    UINT8 protocol;
    UINT16 local_port, remote_port;
    BYTE remote[16];
    UINT64 weight;
    bool permitted;
} flow;
typedef struct evaluation {
    flow cases[128];
    size_t count;
    unsigned filters, fail_at;
    bool keys[SBW_KILL_FILTER_SLOTS];
} evaluation;
static bool equal_guid(const GUID *left, const GUID *right) { return !memcmp(left, right, sizeof(*left)); }
static bool matches(const flow *candidate, const FWPM_FILTER_CONDITION0 *condition) {
    const FWP_CONDITION_VALUE0 *value = &condition->conditionValue;
    if (equal_guid(&condition->fieldKey, &sbw_kill_app_id))
        return value->type == FWP_BYTE_BLOB_TYPE && strlen(candidate->application) == value->byteBlob->size &&
               !memcmp(candidate->application, value->byteBlob->data, value->byteBlob->size);
    if (equal_guid(&condition->fieldKey, &sbw_kill_flags))
        return value->type == FWP_UINT32 && condition->matchType == FWP_MATCH_FLAGS_ALL_SET &&
               (candidate->flags & value->uint32) == value->uint32;
    if (equal_guid(&condition->fieldKey, &sbw_kill_nexthop) ||
        equal_guid(&condition->fieldKey, &sbw_kill_arrival))
        return value->type == FWP_UINT64 && candidate->interface_luid == *value->uint64;
    if (equal_guid(&condition->fieldKey, &sbw_kill_protocol))
        return value->type == FWP_UINT8 && candidate->protocol == value->uint8;
    if (equal_guid(&condition->fieldKey, &sbw_kill_local_port))
        return value->type == FWP_UINT16 && candidate->local_port == value->uint16;
    if (equal_guid(&condition->fieldKey, &sbw_kill_remote_port))
        return value->type == FWP_UINT16 && candidate->remote_port == value->uint16;
    if (equal_guid(&condition->fieldKey, &sbw_kill_remote_address)) {
        CHECK(value->type == FWP_V6_ADDR_MASK);
        unsigned bits = value->v6AddrMask->prefixLength;
        CHECK(bits <= 128);
        for (unsigned i = 0; i < 16 && bits; ++i) {
            BYTE mask = (BYTE)(bits >= 8 ? 255U : 255U << (8 - bits));
            if ((candidate->remote[i] & mask) != (value->v6AddrMask->addr[i] & mask))
                return false;
            bits = bits > 8 ? bits - 8 : 0;
        }
        return true;
    }
    CHECK(false);
    return false;
}
static DWORD observe(void *context, const FWPM_FILTER0 *filter) {
    evaluation *set = context;
    ++set->filters;
    if (set->fail_at == set->filters)
        return ERROR_ACCESS_DENIED;
    CHECK(filter->flags == SBW_KILL_PERSISTENT && filter->weight.type == FWP_UINT64);
    CHECK(filter->providerKey && equal_guid(filter->providerKey, &sbw_kill_provider_key));
    CHECK(equal_guid(&filter->subLayerKey, &sbw_kill_sublayer_key));
    unsigned key = (unsigned)filter->filterKey.Data4[6] * 256 + filter->filterKey.Data4[7];
    CHECK(key < SBW_KILL_FILTER_SLOTS && !set->keys[key]);
    set->keys[key] = true;
    GUID expected = sbw_kill_filter_key(key);
    CHECK(equal_guid(&expected, &filter->filterKey));
    for (size_t i = 0; i < set->count; ++i) {
        flow *candidate = &set->cases[i];
        if (!equal_guid(&filter->layerKey, &sbw_kill_layers[candidate->layer]))
            continue;
        bool match = true;
        for (UINT32 j = 0; j < filter->numFilterConditions; ++j)
            if (!matches(candidate, &filter->filterCondition[j]))
                match = false;
        if (match && *filter->weight.uint64 > candidate->weight) {
            candidate->weight = *filter->weight.uint64;
            candidate->permitted = filter->action.type == FWP_ACTION_PERMIT;
        }
    }
    return ERROR_SUCCESS;
}
static flow *add(evaluation *set, unsigned layer, const char *app, UINT64 interface_luid, UINT8 protocol,
                 UINT16 local, UINT16 remote) {
    CHECK(set->count < sizeof(set->cases) / sizeof(*set->cases));
    flow *item = &set->cases[set->count++];
    memset(item, 0, sizeof(*item));
    item->layer = layer;
    item->application = app;
    item->interface_luid = interface_luid;
    item->protocol = protocol;
    item->local_port = local;
    item->remote_port = remote;
    return item;
}
static FWP_BYTE_BLOB app_blob(const char *name) {
    FWP_BYTE_BLOB result = {(UINT32)strlen(name), (UINT8 *)name};
    return result;
}
int main(void) {
    sbj *observed = sbj_object(), *yes = sbj_bool(true), *no = sbj_bool(false), *invalid = sbj_int(0);
    sbj_set_int(observed, "filter_count", 24);
    CHECK(sbw_kill_switch_startup_action(NULL, observed) == SBW_KILL_PRESERVE_UNKNOWN);
    CHECK(sbw_kill_switch_startup_action(invalid, observed) == SBW_KILL_PRESERVE_UNKNOWN);
    CHECK(sbw_kill_switch_startup_action(yes, observed) == SBW_KILL_ENABLE);
    CHECK(sbw_kill_switch_startup_action(no, observed) == SBW_KILL_DISABLE);
    sbj_set_int(observed, "filter_count", 0);
    CHECK(sbw_kill_switch_startup_action(NULL, observed) == SBW_KILL_UNCHANGED);
    CHECK(sbw_kill_switch_startup_action(no, observed) == SBW_KILL_UNCHANGED);
    CHECK(sbw_kill_switch_startup_action(yes, observed) == SBW_KILL_ENABLE);
    sbj_free(observed); sbj_free(yes); sbj_free(no); sbj_free(invalid);
    FWP_BYTE_BLOB service = app_blob("fixed-service"), core = app_blob("pinned-core"),
                  dhcp = app_blob("system-svchost");
    for (unsigned connected = 0; connected < 2; ++connected) {
        evaluation set = {0};
        for (unsigned layer = 0; layer < 4; ++layer) {
            size_t start = set.count;
            add(&set, layer, "browser", 88, IPPROTO_TCP, 50000, 443);
            add(&set, layer, "browser", 88, IPPROTO_UDP, 50000, 443);
            add(&set, layer, "system-svchost", 88, IPPROTO_UDP, 50000, 53);
            add(&set, layer, "browser", 88, IPPROTO_TCP, 50000, 53);
            add(&set, layer, "browser", 88, IPPROTO_UDP, (UINT16)((layer & 1) ? 546 : 68),
                (UINT16)((layer & 1) ? 547 : 67));
            add(&set, layer, "fixed-service", 88, IPPROTO_TCP, 50000, 443);
            add(&set, layer, "pinned-core", 88, IPPROTO_UDP, 50000, 443);
            add(&set, layer, "system-svchost", 88, IPPROTO_UDP, (UINT16)((layer & 1) ? 546 : 68),
                (UINT16)((layer & 1) ? 547 : 67));
            add(&set, layer, "browser", 88, IPPROTO_TCP, 50000, 80)->flags = FWP_CONDITION_FLAG_IS_LOOPBACK;
            add(&set, layer, "browser", 777, IPPROTO_TCP, 50000, 443);
            add(&set, layer, "system-svchost", 777, IPPROTO_UDP, 50000, 53);
            CHECK(set.count == start + 11);
        }
        CHECK(!sbw_kill_switch_build(&service, &core, &dhcp, connected ? 777 : 0, observe, &set));
        CHECK(set.filters == (connected ? 40u : 36u));
        for (unsigned layer = 0; layer < 4; ++layer) {
            for (unsigned i = 0; i < 5; ++i)
                CHECK(!set.cases[layer * 11 + i].permitted);
            for (unsigned i = 5; i < 9; ++i)
                CHECK(set.cases[layer * 11 + i].permitted);
            for (unsigned i = 9; i < 11; ++i)
                CHECK(set.cases[layer * 11 + i].permitted == (connected != 0));
        }
    }
    evaluation ndp = {0};
    for (unsigned layer = 1; layer < 4; layer += 2) {
        for (unsigned type = 133; type <= 136; ++type) {
            flow *item = add(&ndp, layer, "system", 88, IPPROTO_ICMPV6, (UINT16)type, 0);
            item->remote[0] = 0xfe;
            item->remote[1] = 0x80;
            item = add(&ndp, layer, "system", 88, IPPROTO_ICMPV6, (UINT16)type, 0);
            item->remote[0] = 0xff;
            item->remote[1] = 0x02;
        }
        add(&ndp, layer, "browser", 88, IPPROTO_ICMPV6, 128, 0)->remote[0] = 0x20;
        add(&ndp, layer, "browser", 88, IPPROTO_ICMPV6, 135, 0)->remote[0] = 0x20;
        flow *invalid_flow = add(&ndp, layer, "browser", 88, IPPROTO_ICMPV6, 135, 1);
        invalid_flow->remote[0] = 0xfe;
        invalid_flow->remote[1] = 0x80;
    }
    CHECK(!sbw_kill_switch_build(&service, &core, &dhcp, 0, observe, &ndp));
    for (unsigned layer = 0; layer < 2; ++layer) {
        for (unsigned i = 0; i < 8; ++i)
            CHECK(ndp.cases[layer * 11 + i].permitted);
        for (unsigned i = 8; i < 11; ++i)
            CHECK(!ndp.cases[layer * 11 + i].permitted);
    }
    evaluation failure = {0};
    failure.fail_at = 7;
    CHECK(sbw_kill_switch_build(&service, &core, &dhcp, 0, observe, &failure) == ERROR_ACCESS_DENIED &&
          failure.filters == 7);
    CHECK(sbw_kill_switch_build(NULL, &core, &dhcp, 0, observe, &failure) == ERROR_INVALID_PARAMETER);
    puts("WFP policy: dual-stack TCP/UDP/DNS blocking, pinned app and TUN exceptions, constrained DHCP/NDP, "
         "stable persistent identities passed; host firewall unchanged.");
    return 0;
}
