#ifndef CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#endif
#include "release_trust.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <msi.h>
#include <msiquery.h>
#include <propidl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int invalid(sbw_error *error) {
    return sbw_fail(error, "UPDATE_MANIFEST_INVALID", "The signed release manifest is invalid or incompatible.");
}
static bool hex_string(const char *text, size_t length) {
    if (!text || strlen(text) != length) return false;
    for (size_t i = 0; i < length; ++i) if (!strchr("0123456789abcdefABCDEF", text[i])) return false;
    return true;
}
bool sbw_release_version(const char *text, unsigned parts[3]) {
    if (!text || !*text) return false;
    for (unsigned i = 0; i < 3; ++i) {
        if (*text < '0' || *text > '9' || (*text == '0' && text[1] >= '0' && text[1] <= '9')) return false;
        unsigned value = 0;
        while (*text >= '0' && *text <= '9') {
            value = value * 10 + (unsigned)(*text++ - '0');
            if (value > (i == 2 ? 65535U : 255U)) return false;
        }
        parts[i] = value;
        if (i < 2) { if (*text++ != '.') return false; }
    }
    return !*text;
}
int sbw_release_compare(const char *first, const char *second) {
    unsigned a[3], b[3];
    if (!sbw_release_version(first, a) || !sbw_release_version(second, b)) return INT_MIN;
    for (unsigned i = 0; i < 3; ++i) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}
static bool version_field(const sbj *json, const char *key, char output[32]) {
    const char *value = sbj_get_str(json, key, NULL); unsigned parts[3];
    if (!sbw_json_string(sbj_get(json, key), 31, false) || !sbw_release_version(value, parts)) return false;
    strcpy_s(output, 32, value); return true;
}
static bool artifact_name(const char *text) {
    if (!text || strlen(text) < 5 || strlen(text) >= 160 || !((text[0] >= 'A' && text[0] <= 'Z') ||
        (text[0] >= 'a' && text[0] <= 'z') || (text[0] >= '0' && text[0] <= '9'))) return false;
    for (const char *p = text; *p; ++p) if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
        (*p >= '0' && *p <= '9') || strchr("-_.", *p))) return false;
    return !strstr(text, "..");
}
int sbw_release_parse(const char *manifest, size_t length, const char *publisher, sbw_release *out, sbw_error *error) {
    memset(out, 0, sizeof(*out));
    if (!manifest || !length || length > SBW_RELEASE_MANIFEST_LIMIT || !hex_string(publisher, 40)) return invalid(error);
    sbj *json = sbj_parse_strict(manifest, length, NULL, 0);
    bool ok = sbj_is_object(json) && sbj_size(json) == 12 && sbj_get_int(json, "schema", 0) == 2 &&
        sbj_string_is(sbj_get(json, "platform"), "windows") && sbj_string_is(sbj_get(json, "architecture"), "x64") &&
        sbj_string_is(sbj_get(json, "channel"), "stable") && sbj_get_int(json, "protocol_version", 0) == 1 &&
        sbw_json_string(sbj_get(json, "publisher_thumbprint"), 40, false) && hex_string(sbj_get_str(json, "publisher_thumbprint", NULL), 40) &&
        !_stricmp(sbj_get_str(json, "publisher_thumbprint", ""), publisher) &&
        version_field(json, "version", out->version) && version_field(json, "core_version", out->core_version) &&
        version_field(json, "minimum_app_version", out->minimum_app_version) &&
        sbw_json_string(sbj_get(json, "created_at"), 40, false) &&
        sbj_is_number(sbj_get(json, "rollout_percent"));
    int64_t rollout = sbj_get_int(json, "rollout_percent", -1);
    if (!ok || rollout < 0 || rollout > 100 || sbj_get_double(json, "rollout_percent", -1) != (double)rollout) { ok = false; goto done; }
    const sbj *files = sbj_get(json, "files"); unsigned installers = 0;
    ok = sbj_is_array(files) && sbj_size(files) >= 1 && sbj_size(files) <= 4;
    for (size_t i = 0; ok && i < sbj_size(files); ++i) {
        const sbj *entry = sbj_arr_at(files, i); const char *name = sbj_get_str(entry, "name", NULL);
        const char *digest = sbj_get_str(entry, "sha256", NULL); int64_t bytes = sbj_get_int(entry, "bytes", -1);
        ok = sbj_is_object(entry) && sbj_size(entry) == 3 && sbw_json_string(sbj_get(entry, "name"), 159, false) && artifact_name(name) &&
            sbw_json_string(sbj_get(entry, "sha256"), 64, false) && hex_string(digest, 64) &&
            bytes > 0 && (uint64_t)bytes <= SBW_RELEASE_PACKAGE_LIMIT && sbj_get_double(entry, "bytes", -1) == (double)bytes;
        for (size_t j = 0; ok && j < i; ++j) if (!_stricmp(name, sbj_get_str(sbj_arr_at(files, j), "name", ""))) ok = false;
        if (!ok) break;
        const char *extension = strrchr(name, '.');
        if (extension && !strcmp(extension, ".msi")) {
            ++installers; strcpy_s(out->installer, sizeof(out->installer), name);
            strcpy_s(out->sha256, sizeof(out->sha256), digest); out->bytes = (uint64_t)bytes;
        } else if (!extension || strcmp(extension, ".zip")) ok = false;
    }
    ok = ok && installers == 1;
    if (ok) { out->rollout_percent = (unsigned)rollout; ok = sbw_release_hash(manifest, length, out->id, error) == 0; }
done:
    sbj_free(json);
    if (!ok) { memset(out, 0, sizeof(*out)); return invalid(error); }
    return 0;
}
int sbw_release_eligible(const sbw_release *release, const char *current, unsigned cohort, sbw_error *error) {
    int comparison = sbw_release_compare(release->version, current);
    int minimum = sbw_release_compare(current, release->minimum_app_version);
    if (comparison == INT_MIN || minimum == INT_MIN || minimum < 0) return invalid(error);
    if (comparison <= 0) return sbw_fail(error, "UPDATE_NOT_NEWER", "This release is not newer than the installed application.");
    if (cohort >= 100 || cohort >= release->rollout_percent)
        return sbw_fail(error, "UPDATE_ROLLOUT_PENDING", "This signed release has not reached this installation's rollout group.");
    return 0;
}
static void digest_hex(const BYTE bytes[32], char output[65]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) { output[i * 2] = digits[bytes[i] >> 4]; output[i * 2 + 1] = digits[bytes[i] & 15]; }
    output[64] = 0;
}
int sbw_release_hash(const void *data, size_t length, char output[65], sbw_error *error) {
    BCRYPT_ALG_HANDLE algorithm = NULL; BCRYPT_HASH_HANDLE hash = NULL; BYTE digest[32]; int result = -1;
    if (length <= ULONG_MAX && BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0 &&
        BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) >= 0 &&
        BCryptHashData(hash, (PUCHAR)data, (ULONG)length, 0) >= 0 && BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0) {
        digest_hex(digest, output); result = 0;
    }
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return result ? sbw_fail(error, "UPDATE_HASH_FAILED", "The release digest could not be computed.") : 0;
}
int sbw_release_hash_file(HANDLE file, uint64_t size, const char *expected, sbw_error *error) {
    LARGE_INTEGER actual, zero = {0}; BCRYPT_ALG_HANDLE algorithm = NULL; BCRYPT_HASH_HANDLE hash = NULL;
    BYTE bytes[65536], digest[32]; char hex[65]; uint64_t total = 0; bool ok = false;
    if (!hex_string(expected, 64) || size > SBW_RELEASE_PACKAGE_LIMIT || !GetFileSizeEx(file, &actual) ||
        actual.QuadPart < 0 || (uint64_t)actual.QuadPart != size || !SetFilePointerEx(file, zero, NULL, FILE_BEGIN)) goto done;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0 ||
        BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) < 0) goto done;
    while (total < size) {
        DWORD read = 0;
        if (!ReadFile(file, bytes, sizeof(bytes), &read, NULL) || !read || read > size - total ||
            BCryptHashData(hash, bytes, read, 0) < 0) goto done;
        total += read;
    }
    if (BCryptFinishHash(hash, digest, sizeof(digest), 0) < 0) goto done;
    digest_hex(digest, hex); ok = !_stricmp(expected, hex);
done:
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    SetFilePointerEx(file, zero, NULL, FILE_BEGIN);
    return ok ? 0 : sbw_fail(error, "UPDATE_HASH_MISMATCH", "The installer size or digest does not match the signed release.");
}
static bool certificate_pin(PCCERT_CONTEXT certificate, const char *expected) {
    if (!certificate || !hex_string(expected, 40)) return false;
    BYTE digest[20]; DWORD size = sizeof(digest); char hex[41];
    if (!CertGetCertificateContextProperty(certificate, CERT_SHA1_HASH_PROP_ID, digest, &size) || size != sizeof(digest)) return false;
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i) { hex[i * 2] = digits[digest[i] >> 4]; hex[i * 2 + 1] = digits[digest[i] & 15]; }
    hex[40] = 0; return !_stricmp(hex, expected);
}
static bool certificate_eku(PCCERT_CONTEXT certificate) {
    DWORD size = 0;
    if (!CertGetEnhancedKeyUsage(certificate, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, NULL, &size) || !size || size > 16384) return false;
    PCERT_ENHKEY_USAGE usage = sb_xcalloc(size, 1); bool found = false;
    if (CertGetEnhancedKeyUsage(certificate, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, usage, &size))
        for (DWORD i = 0; i < usage->cUsageIdentifier; ++i) if (!strcmp(usage->rgpszUsageIdentifier[i], szOID_PKIX_KP_CODE_SIGNING)) found = true;
    free(usage); return found;
}
static bool certificate_trusted(PCCERT_CONTEXT certificate, HCERTSTORE extra) {
    CERT_CHAIN_PARA options = {0}; options.cbSize = sizeof(options); options.dwUrlRetrievalTimeout = 5000;
    LPSTR usage = szOID_PKIX_KP_CODE_SIGNING;
    options.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    options.RequestedUsage.Usage.cUsageIdentifier = 1; options.RequestedUsage.Usage.rgpszUsageIdentifier = &usage;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    bool valid = CertGetCertificateChain(NULL, certificate, NULL, extra, &options,
        CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT | CERT_CHAIN_DISABLE_MD2_MD4, NULL, &chain) != FALSE;
    if (valid) {
        CERT_CHAIN_POLICY_PARA policy = {0}; policy.cbSize = sizeof(policy);
        CERT_CHAIN_POLICY_STATUS status = {0}; status.cbSize = sizeof(status);
        valid = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE, chain, &policy, &status) && !status.dwError;
    }
    if (chain) CertFreeCertificateChain(chain);
    return valid;
}
int sbw_release_verify_manifest(const void *manifest, size_t length, const void *signature, size_t signature_length,
    const char *publisher, sbw_release *out, sbw_error *error) {
    memset(out, 0, sizeof(*out));
    if (!hex_string(publisher, 40)) return sbw_fail(error, "UPDATE_PUBLISHER_UNCONFIGURED", "This build has no trusted release publisher configured.");
    if (!manifest || !length || length > SBW_RELEASE_MANIFEST_LIMIT || !signature || !signature_length ||
        signature_length > SBW_RELEASE_SIGNATURE_LIMIT) return invalid(error);
    CRYPT_DATA_BLOB blob = {(DWORD)signature_length, (BYTE *)signature}; HCERTSTORE store = NULL; HCRYPTMSG message = NULL;
    PCCERT_CONTEXT signer = NULL; bool ok = false; DWORD count = 0, size = sizeof(count);
    if (!CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
        CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL, &store, &message, NULL) ||
        !CryptMsgGetParam(message, CMSG_SIGNER_COUNT_PARAM, 0, &count, &size) || count != 1) goto done;
    size = 0;
    if (!CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, NULL, &size) || !size || size > SBW_RELEASE_SIGNATURE_LIMIT) goto done;
    CMSG_SIGNER_INFO *info = sb_xcalloc(size, 1);
    ok = CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, info, &size) && info->HashAlgorithm.pszObjId &&
        !strcmp(info->HashAlgorithm.pszObjId, szOID_NIST_sha256);
    free(info); if (!ok) goto done; ok = false;
    CRYPT_VERIFY_MESSAGE_PARA parameters = {0}; parameters.cbSize = sizeof(parameters);
    parameters.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    const BYTE *contents[] = {(const BYTE *)manifest}; DWORD lengths[] = {(DWORD)length};
    ok = CryptVerifyDetachedMessageSignature(&parameters, 0, signature, (DWORD)signature_length, 1, contents, lengths, &signer) &&
        certificate_pin(signer, publisher) && certificate_eku(signer) && certificate_trusted(signer, store);
done:
    if (signer) CertFreeCertificateContext(signer);
    if (message) CryptMsgClose(message);
    if (store) CertCloseStore(store, 0);
    if (!ok) return sbw_fail(error, "UPDATE_SIGNATURE_INVALID", "The release publisher signature or certificate chain could not be verified.");
    return sbw_release_parse(manifest, length, publisher, out, error);
}
int sbw_release_verify_file(const wchar_t *path, HANDLE file, const char *publisher, bool timestamp, sbw_error *error) {
    WINTRUST_FILE_INFO info = {0}; info.cbStruct = sizeof(info); info.pcwszFilePath = path; info.hFile = file;
    WINTRUST_DATA data = {0}; data.cbStruct = sizeof(data); data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN; data.dwUnionChoice = WTD_CHOICE_FILE; data.pFile = &info;
    data.dwStateAction = WTD_STATEACTION_VERIFY; data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    bool valid = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &data) == ERROR_SUCCESS;
    if (valid) {
        typedef CRYPT_PROVIDER_DATA *(WINAPI *provider_fn)(HANDLE);
        typedef CRYPT_PROVIDER_SGNR *(WINAPI *signer_fn)(CRYPT_PROVIDER_DATA *, DWORD, BOOL, DWORD);
        provider_fn get_provider = NULL; signer_fn get_signer = NULL;
        HMODULE trust = GetModuleHandleW(L"wintrust.dll");
        FARPROC entry = trust ? GetProcAddress(trust, "WTHelperProvDataFromStateData") : NULL;
        if (sizeof(entry) == sizeof(get_provider)) memcpy(&get_provider, &entry, sizeof(get_provider));
        entry = trust ? GetProcAddress(trust, "WTHelperGetProvSignerFromChain") : NULL;
        if (sizeof(entry) == sizeof(get_signer)) memcpy(&get_signer, &entry, sizeof(get_signer));
        CRYPT_PROVIDER_DATA *provider = get_provider ? get_provider(data.hWVTStateData) : NULL;
        CRYPT_PROVIDER_SGNR *signer = provider && get_signer ? get_signer(provider, 0, FALSE, 0) : NULL;
        valid = provider && provider->csSigners == 1 && signer && !signer->dwError && signer->csCertChain &&
            signer->psSigner && signer->psSigner->HashAlgorithm.pszObjId && !strcmp(signer->psSigner->HashAlgorithm.pszObjId, szOID_NIST_sha256) &&
            certificate_pin(signer->pasCertChain[0].pCert, publisher) && certificate_eku(signer->pasCertChain[0].pCert) &&
            (!timestamp || (signer->csCounterSigners && !signer->pasCounterSigners[0].dwError));
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &data);
    return valid ? 0 : sbw_fail(error, "UPDATE_SIGNATURE_INVALID", "The installer publisher or trusted timestamp could not be verified.");
}
static bool installer_property(MSIHANDLE database, const wchar_t *query, const wchar_t *expected) {
    MSIHANDLE view = 0, row = 0; bool ok = false; wchar_t value[256]; DWORD size = 256;
    if (MsiDatabaseOpenViewW(database, query, &view) == ERROR_SUCCESS && MsiViewExecute(view, 0) == ERROR_SUCCESS &&
        MsiViewFetch(view, &row) == ERROR_SUCCESS && MsiRecordGetStringW(row, 1, value, &size) == ERROR_SUCCESS)
        ok = !_wcsicmp(value, expected);
    if (row) MsiCloseHandle(row);
    if (view) MsiCloseHandle(view);
    return ok;
}
int sbw_release_verify_installer(const wchar_t *path, HANDLE file, const char *publisher, const sbw_release *release, sbw_error *error) {
    if (sbw_release_hash_file(file, release->bytes, release->sha256, error) < 0 ||
        sbw_release_verify_file(path, file, publisher, true, error) < 0) return -1;
    MSIHANDLE database = 0, summary = 0; wchar_t *version = sbw_wide(release->version, error); bool ok = false;
    if (version && MsiOpenDatabaseW(path, MSIDBOPEN_READONLY, &database) == ERROR_SUCCESS) {
        ok = installer_property(database, L"SELECT `Value` FROM `Property` WHERE `Property`='ProductName'", L"sb-easy") &&
            installer_property(database, L"SELECT `Value` FROM `Property` WHERE `Property`='UpgradeCode'", L"{78E985E7-0CDC-4782-B1EA-52DCE6B3E544}") &&
            installer_property(database, L"SELECT `Value` FROM `Property` WHERE `Property`='ProductVersion'", version);
        wchar_t architecture[64]; DWORD length = 64; UINT type = 0;
        ok = ok && MsiGetSummaryInformationW(database, NULL, 0, &summary) == ERROR_SUCCESS &&
            MsiSummaryInfoGetPropertyW(summary, 7 /* PID_TEMPLATE */, &type, NULL, NULL, architecture, &length) == ERROR_SUCCESS &&
            !wcsncmp(architecture, L"x64;", 4);
    }
    if (summary) MsiCloseHandle(summary);
    if (database) MsiCloseHandle(database);
    free(version);
    return ok ? 0 : sbw_fail(error, "UPDATE_PACKAGE_INVALID", "The installer identity, architecture or version does not match this release.");
}
