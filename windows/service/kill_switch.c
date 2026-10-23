#include <winsock2.h>
#include <ws2tcpip.h>
#include "kill_switch_internal.h"

sbw_kill_startup_action sbw_kill_switch_startup_action(const sbj *preference, const sbj *observed) {
    bool existing = sbj_get_int(observed, "filter_count", 0) > 0;
    if (!sbj_is_bool(preference)) return existing ? SBW_KILL_PRESERVE_UNKNOWN : SBW_KILL_UNCHANGED;
    if (sbj_as_bool(preference, false)) return SBW_KILL_ENABLE;
    return existing ? SBW_KILL_DISABLE : SBW_KILL_UNCHANGED;
}
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Stable product identities, independent of installation location/version. */
const GUID sbw_kill_provider_key = {
    0x87296c3a, 0xcaa3, 0x4468, {0x9a, 0xda, 0x56, 0xa7, 0xb7, 0x54, 0xfa, 0x1b}};
const GUID sbw_kill_sublayer_key = {
    0x5a84217f, 0x74ac, 0x4673, {0x90, 0x7c, 0x98, 0x4b, 0xa9, 0x0c, 0x06, 0x34}};

/* Windows SDK identifiers. Private names also support MinGW versions which
 * declare WFP APIs/structures but omit the built-in identifier declarations.
 * Source: Microsoft win32metadata generation/WinSDK/RecompiledIdlHeaders/um/fwpmu.h. */
const GUID sbw_kill_layers[4] = {
    {0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}},
    {0x4a72393b, 0x319f, 0x44bc, {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}},
    {0xe1cd9fe7, 0xf4b5, 0x4273, {0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}},
    {0xa3b42c97, 0x9f04, 0x4672, {0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}};
const GUID sbw_kill_app_id = {0xd78e1e87, 0x8644, 0x4ea5, {0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}};
const GUID sbw_kill_flags = {0x632ce23b, 0x5167, 0x435c, {0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}};
const GUID sbw_kill_nexthop = {0x93ae8f5b, 0x7f6f, 0x4719, {0x98, 0xc8, 0x14, 0xe9, 0x74, 0x29, 0xef, 0x04}};
const GUID sbw_kill_arrival = {0x618a9b6d, 0x386b, 0x4136, {0xad, 0x6e, 0xb5, 0x15, 0x87, 0xcf, 0xb1, 0xcd}};
const GUID sbw_kill_protocol = {0x3971ef2b, 0x623e, 0x4f9a, {0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}};
const GUID sbw_kill_local_port = {
    0x0c1ba1af, 0x5765, 0x453f, {0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}};
const GUID sbw_kill_remote_port = {
    0xc35a604d, 0xd22b, 0x4e1a, {0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}};
const GUID sbw_kill_remote_address = {
    0xb235ae9a, 0x1d64, 0x49b8, {0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}};

GUID sbw_kill_filter_key(unsigned index) {
    GUID key = {0xdfbf758a, 0x4dbb, 0x4557, {0x83, 0xbe, 0xd3, 0x19, 0x8a, 0x6f, 0x00, 0x00}};
    key.Data4[6] = (BYTE)(index >> 8);
    key.Data4[7] = (BYTE)index;
    return key;
}
static bool same_guid(const GUID *left, const GUID *right) { return !memcmp(left, right, sizeof(*left)); }
static FWPM_FILTER_CONDITION0 condition(const GUID *key, FWP_DATA_TYPE type) {
    FWPM_FILTER_CONDITION0 result = {0};
    result.fieldKey = *key;
    result.matchType = FWP_MATCH_EQUAL;
    result.conditionValue.type = type;
    return result;
}
static DWORD emit_filter(sbw_kill_filter_sink sink, void *context, unsigned layer, unsigned slot,
                         const wchar_t *name, FWPM_FILTER_CONDITION0 *conditions, UINT32 length) {
    FWPM_FILTER0 filter = {0};
    UINT64 weight = slot == 0 ? 1 : 100 + slot;
    filter.filterKey = sbw_kill_filter_key(layer * 32 + slot);
    filter.displayData.name = (wchar_t *)name;
    filter.flags = SBW_KILL_PERSISTENT;
    filter.providerKey = (GUID *)&sbw_kill_provider_key;
    filter.layerKey = sbw_kill_layers[layer];
    filter.subLayerKey = sbw_kill_sublayer_key;
    filter.weight.type = FWP_UINT64;
    filter.weight.uint64 = &weight;
    filter.action.type = slot == 0 ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
    filter.numFilterConditions = length;
    filter.filterCondition = conditions;
    /* Keep permits soft so other Windows/security policies may still deny. */
    return sink(context, &filter);
}
DWORD sbw_kill_switch_build(const FWP_BYTE_BLOB *service_app, const FWP_BYTE_BLOB *core_app,
                            const FWP_BYTE_BLOB *dhcp_app, UINT64 tun_luid, sbw_kill_filter_sink sink,
                            void *context) {
    if (!service_app || !service_app->size || !core_app || !core_app->size || !dhcp_app || !dhcp_app->size ||
        !sink)
        return ERROR_INVALID_PARAMETER;
    for (unsigned layer = 0; layer < 4; ++layer) {
        DWORD code = emit_filter(sink, context, layer, 0, L"sb-easy: block other traffic", NULL, 0);
        if (code)
            return code;
        FWPM_FILTER_CONDITION0 loopback = condition(&sbw_kill_flags, FWP_UINT32);
        loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
        loopback.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
        code = emit_filter(sink, context, layer, 1, L"sb-easy: loopback", &loopback, 1);
        if (code)
            return code;
        FWPM_FILTER_CONDITION0 app = condition(&sbw_kill_app_id, FWP_BYTE_BLOB_TYPE);
        app.conditionValue.byteBlob = (FWP_BYTE_BLOB *)service_app;
        code = emit_filter(sink, context, layer, 2, L"sb-easy: fixed service recovery", &app, 1);
        if (code)
            return code;
        app.conditionValue.byteBlob = (FWP_BYTE_BLOB *)core_app;
        code = emit_filter(sink, context, layer, 3, L"sb-easy: pinned core transport", &app, 1);
        if (code)
            return code;
        if (tun_luid) {
            FWPM_FILTER_CONDITION0 tun =
                condition(layer < 2 ? &sbw_kill_nexthop : &sbw_kill_arrival, FWP_UINT64);
            tun.conditionValue.uint64 = &tun_luid;
            code = emit_filter(sink, context, layer, 4, L"sb-easy: owned TUN interface", &tun, 1);
            if (code)
                return code;
        }
        FWPM_FILTER_CONDITION0 dhcp[4] = {
            condition(&sbw_kill_app_id, FWP_BYTE_BLOB_TYPE), condition(&sbw_kill_protocol, FWP_UINT8),
            condition(&sbw_kill_local_port, FWP_UINT16), condition(&sbw_kill_remote_port, FWP_UINT16)};
        dhcp[0].conditionValue.byteBlob = (FWP_BYTE_BLOB *)dhcp_app;
        dhcp[1].conditionValue.uint8 = IPPROTO_UDP;
        dhcp[2].conditionValue.uint16 = (UINT16)((layer & 1) ? 546 : 68);
        dhcp[3].conditionValue.uint16 = (UINT16)((layer & 1) ? 547 : 67);
        code = emit_filter(sink, context, layer, 5, L"sb-easy: Windows DHCP only", dhcp, 4);
        if (code)
            return code;
        if (layer & 1) {
            /* Only local-link NDP; no generic ICMPv6 or multicast exemption. */
            for (unsigned kind = 0; kind < 4; ++kind)
                for (unsigned scope = 0; scope < 2; ++scope) {
                    FWP_V6_ADDR_AND_MASK address = {0};
                    address.addr[0] = scope ? 0xff : 0xfe;
                    address.addr[1] = scope ? 0x02 : 0x80;
                    address.prefixLength = (UINT8)(scope ? 16 : 10);
                    FWPM_FILTER_CONDITION0 ndp[4] = {condition(&sbw_kill_protocol, FWP_UINT8),
                                                     condition(&sbw_kill_local_port, FWP_UINT16),
                                                     condition(&sbw_kill_remote_port, FWP_UINT16),
                                                     condition(&sbw_kill_remote_address, FWP_V6_ADDR_MASK)};
                    ndp[0].conditionValue.uint8 = IPPROTO_ICMPV6;
                    ndp[1].conditionValue.uint16 = (UINT16)(133 + kind);
                    ndp[2].conditionValue.uint16 = 0;
                    ndp[3].conditionValue.v6AddrMask = &address;
                    code = emit_filter(sink, context, layer, 6 + kind * 2 + scope, L"sb-easy: local-link NDP",
                                       ndp, 4);
                    if (code)
                        return code;
                }
        }
    }
    return ERROR_SUCCESS;
}
static DWORD engine_open(HANDLE *engine) {
    FWPM_SESSION0 session = {0};
    session.displayData.name = L"sb-easy persistent network protection";
    session.txnWaitTimeoutInMSec = 5000;
    /* Deliberately not FWPM_SESSION_FLAG_DYNAMIC. */
    return FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, engine);
}
static DWORD add_filter(void *engine, const FWPM_FILTER0 *filter) {
    return FwpmFilterAdd0(engine, filter, NULL, NULL);
}
static DWORD delete_filters(HANDLE engine) {
    for (unsigned i = 0; i < SBW_KILL_FILTER_SLOTS; ++i) {
        GUID key = sbw_kill_filter_key(i);
        DWORD code = FwpmFilterDeleteByKey0(engine, &key);
        if (code != ERROR_SUCCESS && code != (DWORD)FWP_E_FILTER_NOT_FOUND)
            return code;
    }
    return ERROR_SUCCESS;
}
static DWORD ensure_provider(HANDLE engine) {
    FWPM_PROVIDER0 provider = {0};
    provider.providerKey = sbw_kill_provider_key;
    provider.displayData.name = L"sb-easy network protection";
    provider.flags = SBW_KILL_PERSISTENT;
    /* BFE disables persistent provider filters after restart unless its service
     * exists and is auto-start. The installer uses this exact SCM service name. */
    provider.serviceName = L"sb-easy";
    DWORD code = FwpmProviderAdd0(engine, &provider, NULL);
    if (code != ERROR_SUCCESS && code != (DWORD)FWP_E_ALREADY_EXISTS)
        return code;
    FWPM_SUBLAYER0 layer = {0};
    layer.subLayerKey = sbw_kill_sublayer_key;
    layer.displayData.name = L"sb-easy network protection";
    layer.providerKey = (GUID *)&sbw_kill_provider_key;
    layer.flags = SBW_KILL_PERSISTENT;
    layer.weight = 0x8000;
    code = FwpmSubLayerAdd0(engine, &layer, NULL);
    return code == (DWORD)FWP_E_ALREADY_EXISTS ? ERROR_SUCCESS : code;
}
static DWORD remove_provider(HANDLE engine) {
    DWORD code = FwpmSubLayerDeleteByKey0(engine, &sbw_kill_sublayer_key);
    if (code != ERROR_SUCCESS && code != (DWORD)FWP_E_SUBLAYER_NOT_FOUND)
        return code;
    code = FwpmProviderDeleteByKey0(engine, &sbw_kill_provider_key);
    return code == (DWORD)FWP_E_PROVIDER_NOT_FOUND ? ERROR_SUCCESS : code;
}
static DWORD persistence_service_check(void) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager)
        return GetLastError();
    SC_HANDLE service = OpenServiceW(manager, L"sb-easy", SERVICE_QUERY_CONFIG);
    DWORD code = service ? ERROR_SUCCESS : GetLastError();
    if (service) {
        DWORD size = 0;
        (void)QueryServiceConfigW(service, NULL, 0, &size);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !size || size > 65536)
            code = ERROR_INVALID_DATA;
        else {
            QUERY_SERVICE_CONFIGW *config = sb_xcalloc(1, size);
            if (!QueryServiceConfigW(service, config, size, &size))
                code = GetLastError();
            else if (config->dwStartType != SERVICE_AUTO_START)
                code = ERROR_SERVICE_DISABLED;
            free(config);
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
    return code;
}
int sbw_kill_switch_apply(bool enabled, const wchar_t *core_executable, const wchar_t *tun_alias,
                          sbw_error *error) {
    HANDLE engine = NULL;
    FWP_BYTE_BLOB *service = NULL, *core = NULL, *dhcp = NULL;
    DWORD code = ERROR_SUCCESS;
    NET_LUID tun = {0};
    bool tun_missing = false;
    if (enabled) {
        code = persistence_service_check();
        if (code)
            return sbw_fail(error, "KILL_SWITCH_SERVICE_REQUIRED",
                            "Install and enable automatic startup for the sb-easy service first.");
        wchar_t executable[32768], system_path[32768];
        DWORD length = GetModuleFileNameW(NULL, executable, 32768);
        UINT system_length = GetSystemDirectoryW(system_path, 32768);
        if (!core_executable || !*core_executable || !length || length >= 32768 || !system_length ||
            system_length >= 32768 - 13 || wcscat_s(system_path, 32768, L"\\svchost.exe")) {
            code = ERROR_INVALID_PARAMETER;
            goto done;
        }
        code = FwpmGetAppIdFromFileName0(executable, &service);
        if (!code)
            code = FwpmGetAppIdFromFileName0(core_executable, &core);
        if (!code)
            code = FwpmGetAppIdFromFileName0(system_path, &dhcp);
        if (code)
            goto done;
        if (tun_alias && *tun_alias && ConvertInterfaceAliasToLuid(tun_alias, &tun) != NO_ERROR) {
            tun_missing = true;
            code = ERROR_NOT_FOUND;
            goto done;
        }
    }
    code = engine_open(&engine);
    if (code)
        goto done;
    code = FwpmTransactionBegin0(engine, 0);
    if (code)
        goto done;
    code = enabled ? ensure_provider(engine) : ERROR_SUCCESS;
    if (!code)
        code = delete_filters(engine);
    if (!code)
        code = enabled ? sbw_kill_switch_build(service, core, dhcp, tun.Value, add_filter, engine)
                       : remove_provider(engine);
    if (!code)
        code = FwpmTransactionCommit0(engine);
    if (code)
        (void)FwpmTransactionAbort0(engine);
done:
    if (service)
        FwpmFreeMemory0((void **)&service);
    if (core)
        FwpmFreeMemory0((void **)&core);
    if (dhcp)
        FwpmFreeMemory0((void **)&dhcp);
    if (engine)
        (void)FwpmEngineClose0(engine);
    if (code)
        return sbw_fail(error, tun_missing ? "KILL_SWITCH_TUN_UNAVAILABLE" : "KILL_SWITCH_FAILED",
                        tun_missing ? "The owned TUN interface is not available for network protection."
                                    : "Windows network protection could not be updated.");
    return 0;
}
sbj *sbw_kill_switch_status(void) {
    sbj *result = sbj_object();
    HANDLE engine = NULL;
    DWORD code = engine_open(&engine);
    UINT32 count = 0;
    unsigned denied = 0, tun = 0;
    bool disabled = false, exists = false;
    if (!code) {
        FWPM_PROVIDER0 *provider = NULL;
        code = FwpmProviderGetByKey0(engine, &sbw_kill_provider_key, &provider);
        if (code == (DWORD)FWP_E_PROVIDER_NOT_FOUND)
            code = ERROR_SUCCESS;
        else if (!code) {
            exists = true;
            disabled = (provider->flags & 2U) != 0;
        }
        if (provider)
            FwpmFreeMemory0((void **)&provider);
    }
    for (unsigned layer = 0; exists && !code && layer < 4; ++layer) {
        HANDLE iterator = NULL;
        FWPM_FILTER_ENUM_TEMPLATE0 query = {0};
        query.providerKey = (GUID *)&sbw_kill_provider_key;
        query.layerKey = sbw_kill_layers[layer];
        query.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
        query.flags = FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
        query.actionMask = 0xffffffffU;
        code = FwpmFilterCreateEnumHandle0(engine, &query, &iterator);
        if (code)
            break;
        FWPM_FILTER0 **filters = NULL;
        UINT32 received = 0;
        code = FwpmFilterEnum0(engine, iterator, SBW_KILL_FILTER_SLOTS, &filters, &received);
        if (!code)
            for (UINT32 i = 0; i < received; ++i) {
                const FWPM_FILTER0 *filter = filters[i];
                ++count;
                if (filter->flags & SBW_KILL_DISABLED)
                    disabled = true;
                GUID key = sbw_kill_filter_key(layer * 32);
                if (same_guid(&filter->filterKey, &key) &&
                    same_guid(&filter->layerKey, &sbw_kill_layers[layer]) &&
                    same_guid(&filter->subLayerKey, &sbw_kill_sublayer_key) && !filter->numFilterConditions &&
                    (filter->flags & SBW_KILL_PERSISTENT) && !(filter->flags & SBW_KILL_DISABLED) &&
                    filter->action.type == FWP_ACTION_BLOCK)
                    denied |= 1U << layer;
                key = sbw_kill_filter_key(layer * 32 + 4);
                if (same_guid(&filter->filterKey, &key))
                    tun |= 1U << layer;
            }
        if (filters)
            FwpmFreeMemory0((void **)&filters);
        (void)FwpmFilterDestroyEnumHandle0(engine, iterator);
        if (received >= SBW_KILL_FILTER_SLOTS)
            code = ERROR_INVALID_DATA;
    }
    if (engine)
        (void)FwpmEngineClose0(engine);
    bool active = !code && !disabled && denied == 15U && count >= 36U;
    sbj_set_bool(result, "available", code == ERROR_SUCCESS);
    sbj_set_bool(result, "enabled", active);
    sbj_set_bool(result, "persistent", active);
    sbj_set_bool(result, "tun_allowed", active && tun == 15U);
    sbj_set_int(result, "filter_count", count);
    sbj_set_str(result, "error_code",
                code                ? "KILL_SWITCH_UNAVAILABLE"
                : exists && !active ? "KILL_SWITCH_INCOMPLETE"
                                    : "");
    return result;
}
bool sbw_kill_switch_recovery_disabled(void) {
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\sb-easy", 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) !=
        ERROR_SUCCESS)
        return false;
    DWORD value = 0, type = 0, size = sizeof(value);
    LSTATUS code = RegQueryValueExW(key, L"KillSwitchRecoveryDisabled", NULL, &type, (BYTE *)&value, &size);
    RegCloseKey(key);
    return code == ERROR_SUCCESS && type == REG_DWORD && size == sizeof(value) && value == 1;
}
int sbw_kill_switch_set_recovery_disabled(bool disabled, sbw_error *error) {
    HKEY key = NULL;
    LSTATUS code =
        disabled ? RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\sb-easy", 0, NULL, REG_OPTION_NON_VOLATILE,
                                   KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &key, NULL)
                 : RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\sb-easy", 0, KEY_SET_VALUE | KEY_WOW64_64KEY,
                                 &key);
    if (!disabled && code == ERROR_FILE_NOT_FOUND)
        return 0;
    if (code == ERROR_SUCCESS) {
        DWORD value = 1;
        code = disabled ? RegSetValueExW(key, L"KillSwitchRecoveryDisabled", 0, REG_DWORD,
                                         (const BYTE *)&value, sizeof(value))
                        : RegDeleteValueW(key, L"KillSwitchRecoveryDisabled");
        if (!disabled && code == ERROR_FILE_NOT_FOUND)
            code = ERROR_SUCCESS;
        if (code == ERROR_SUCCESS)
            code = RegFlushKey(key);
        RegCloseKey(key);
    }
    if (code != ERROR_SUCCESS)
        return sbw_fail(error, "KILL_SWITCH_RECOVERY_FAILED",
                        "The machine network-protection recovery preference could not be saved.");
    return 0;
}
