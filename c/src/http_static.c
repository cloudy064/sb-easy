/* Static files with Drogon semantics (StaticFileRouter): MIME table, ranges,
 * precompressed variants and the document-root fallback. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

#include "http_wire.h"

/* ---- static files (Drogon semantics) ------------------------------------ */

/* drogon::getContentType(fileName) + contentTypeToMime(): the extension after
 * the last '.' of the whole path, lowercased. */
static const char *drogon_mime_for(const char *path) {
    static const char *const table[][2] = {
        {"aac", "audio/aac"}, {"ac3", "audio/ac3"}, {"aif", "audio/aiff"}, {"aifc", "audio/aiff"},
        {"aiff", "audio/aiff"}, {"apg", "video/apg"}, {"ape", "audio/x-ape"}, {"apng", "image/apng"},
        {"av1", "video/av01"}, {"avi", "video/x-msvideo"}, {"avif", "image/avif"}, {"bmp", "image/bmp"},
        {"bz", "application/x-bzip"}, {"bz2", "application/x-bzip2"}, {"css", "text/css; charset=utf-8"},
        {"csv", "text/csv; charset=utf-8"}, {"doc", "application/msword"},
        {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {"eot", "application/vnd.ms-fontobject"}, {"flac", "audio/flac"}, {"gif", "image/gif"},
        {"gz", "application/gzip"}, {"htm", "text/html; charset=utf-8"}, {"html", "text/html; charset=utf-8"},
        {"icns", "image/icns"}, {"ico", "image/vnd.microsoft.icon"}, {"j2k", "image/jp2"},
        {"jar", "application/java-archive"}, {"j2c", "image/jp2"}, {"jp2", "image/jp2"}, {"jpeg", "image/jpeg"},
        {"jpc", "image/jp2"}, {"jpf", "image/jp2"}, {"jpg", "image/jpeg"}, {"jpg2", "image/jp2"},
        {"jpm", "image/jp2"}, {"jpx", "image/jp2"}, {"js", "text/javascript; charset=utf-8"},
        {"json", "application/json; charset=utf-8"}, {"lzma", "application/x-xz"}, {"m1a", "audio/mpeg"},
        {"m1v", "video/mpeg"}, {"m2a", "audio/mpeg"}, {"m2ts", "video/mp2t"}, {"m2v", "video/mpeg"},
        {"m4a", "audio/mp4"}, {"m4v", "video/x-m4v"}, {"mjs", "text/javascript; charset=utf-8"},
        {"mka", "audio/matroska"}, {"mkv", "video/matroska"}, {"mng", "image/x-mng"},
        {"mov", "video/quicktime"}, {"mp1", "audio/mpeg"}, {"mp2", "audio/mpeg"}, {"mp3", "audio/mpeg"},
        {"mp4", "video/mp4"}, {"mpa", "audio/mpeg"}, {"mpe", "video/mpeg"}, {"mpeg", "video/mpeg"},
        {"mpg", "video/mpeg"}, {"mpv", "video/mpeg"}, {"oga", "audio/ogg"}, {"ogg", "audio/ogg"},
        {"ogv", "video/ogg"}, {"otf", "application/x-font-opentype"}, {"pdf", "application/pdf"},
        {"php", "application/x-httpd-php"}, {"png", "image/png"}, {"rar", "application/vnd.rar"},
        {"svg", "image/svg+xml"}, {"tar", "application/x-tar"}, {"targa", "image/x-tga"},
        {"tif", "image/tiff"}, {"tiff", "image/tiff"}, {"tga", "image/x-tga"}, {"tgz", "application/x-tgz"},
        {"ts", "video/mp2t"}, {"tta", "audio/x-tta"}, {"ttf", "application/x-font-truetype"},
        {"txt", "text/plain; charset=utf-8"}, {"w64", "audio/wav"}, {"wav", "audio/wav"},
        {"wave", "audio/wav"}, {"wasm", "application/wasm"}, {"weba", "audio/webm"}, {"webm", "video/webm"},
        {"webp", "image/webp"}, {"wma", "audio/x-ms-wma"}, {"woff", "application/font-woff"},
        {"woff2", "application/font-woff2"}, {"wv", "audio/x-wavpack"},
        {"xht", "application/xhtml+xml; charset=utf-8"}, {"xhtml", "application/xhtml+xml; charset=utf-8"},
        {"xml", "application/xml; charset=utf-8"}, {"xsl", "text/xsl; charset=utf-8"},
        {"xz", "application/x-xz"}, {"zip", "application/zip"}, {"7z", "application/x-7z-compressed"},
    };
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    for (size_t i = 0; i < sizeof table / sizeof table[0]; ++i)
        if (strcasecmp(table[i][0], dot + 1) == 0) return table[i][1];
    return "application/octet-stream";
}

/* StaticFileRouter::fileTypeSet_ defaults. */
static bool drogon_static_file_type(const char *lowered_extension) {
    static const char *const types[] = {"html", "js",  "css",   "xml",  "xsl", "txt", "svg",
                                        "ttf",  "otf", "woff2", "woff", "eot", "png", "jpg",
                                        "jpeg", "gif", "bmp",   "ico",  "icns"};
    for (size_t i = 0; i < sizeof types / sizeof types[0]; ++i)
        if (strcmp(types[i], lowered_extension) == 0) return true;
    return false;
}

/* HttpResponse::newFileResponse(path[, offset, length]): the file must be
 * readable, else Drogon answers with its 404 page. */
static bool wire_file(wire_response *w, const char *path, uint64_t offset, uint64_t length) {
    FILE *f = fopen(path, "rb");
    struct stat st;
    if (!f || fstat(fileno(f), &st) != 0) {
        if (f) fclose(f);
        wire_not_found_page(w);
        return false;
    }
    fclose(f);
    uint64_t size = (uint64_t)st.st_size;
    w->status = 200;
    sb_str_set(&w->file, path);
    w->file_offset = offset;
    w->file_length = length ? length : size - offset;
    sb_str_set(&w->content_type, drogon_mime_for(path));
    return true;
}

/* static_file_response() from the C++ anonymous namespace. */
void static_file_response(wire_response *w, const char *path, bool immutable) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        wire_error(w, 404, "Static resource not found");
        return;
    }
    wire_file(w, path, 0, 0);
    wire_set_header(w, "Cache-Control", immutable ? "public, max-age=31536000, immutable" : "no-cache");
}

/* safe_static_relative_path(): non-empty, relative, no NUL, no ".." component. */
bool safe_static_relative_path(const char *value, bool has_nul) {
    if (!value || !*value || value[0] == '/' || has_nul) return false;
    sb_strvec parts = sb_split(value, '/');
    bool ok = true;
    for (size_t i = 0; i < parts.len && ok; ++i)
        if (strcmp(parts.items[i], "..") == 0) ok = false;
    sb_strvec_free(&parts);
    return ok;
}

/* ---- Drogon StaticFileRouter fallback ------------------------------------ */

void http_date(time_t t, char *buf, size_t size) {
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, size, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

/* getFileStat(): regular file + its Last-Modified string. */
static bool file_stat(const char *path, struct stat *st, char *modified, size_t modified_size) {
    if (stat(path, st) != 0 || !S_ISREG(st->st_mode)) return false;
    http_date(st->st_mtime, modified, modified_size);
    return true;
}

typedef enum { RANGE_INVALID, RANGE_NOT_SATISFIABLE, RANGE_SINGLE, RANGE_MULTI } range_result;

/* drogon::parseRangeHeader(); only the first range is kept (Drogon answers
 * multi-part requests with the first part). */
static range_result parse_range_header(const char *text, uint64_t content_length, uint64_t *first_start,
                                       uint64_t *first_end) {
    const uint64_t max_ten = UINT64_MAX / 10, max_digit = UINT64_MAX % 10;
    if (strlen(text) < 7 || strncmp(text, "bytes=", 6) != 0) return RANGE_INVALID;
    const char *it = text + 6;
    uint64_t total = 0;
    size_t count = 0;
    for (;;) {
        uint64_t start = 0, end = 0;
        bool suffix = false;
        while (*it == ' ') ++it;
        if (*it == '-') {
            suffix = true;
            ++it;
        } else {
            if (!(*it >= '0' && *it <= '9')) return RANGE_INVALID;
            while (*it >= '0' && *it <= '9') {
                if (start > max_ten || (start >= max_ten && (uint64_t)(*it - '0') > max_digit))
                    return RANGE_NOT_SATISFIABLE;
                start = start * 10 + (uint64_t)(*it++ - '0');
            }
            while (*it == ' ') ++it;
            if (*it++ != '-') return RANGE_INVALID;
            while (*it == ' ') ++it;
            if (*it == ',' || *it == '\0') {
                end = content_length;
                if (start < end) {
                    if (total > UINT64_MAX - (end - start)) return RANGE_NOT_SATISFIABLE;
                    total += end - start;
                    if (count++ == 0) {
                        *first_start = start;
                        *first_end = end;
                    }
                }
                if (*it++ != ',') break;
                continue;
            }
        }
        if (!(*it >= '0' && *it <= '9')) return RANGE_INVALID;
        while (*it >= '0' && *it <= '9') {
            if (end > max_ten || (end >= max_ten && (uint64_t)(*it - '0') > max_digit)) return RANGE_NOT_SATISFIABLE;
            end = end * 10 + (uint64_t)(*it++ - '0');
        }
        while (*it == ' ') ++it;
        if (*it != ',' && *it != '\0') return RANGE_INVALID;
        if (suffix) {
            start = end < content_length ? content_length - end : 0;
            end = content_length - 1;
        }
        if (end >= content_length) end = content_length;
        else ++end;
        if (start < end) {
            if (count++ == 0) {
                *first_start = start;
                *first_end = end;
            }
            if (total > UINT64_MAX - (end - start)) return RANGE_NOT_SATISFIABLE;
            total += end - start;
            if (count > 100) return RANGE_INVALID;
        }
        if (*it++ != ',') break;
    }
    if (count == 0 || total > content_length) return RANGE_NOT_SATISFIABLE;
    return count == 1 ? RANGE_SINGLE : RANGE_MULTI;
}

const char *exchange_header(const http_exchange *ex, const char *name) {
    const char *v = sb_req_header(&ex->req, name);
    return v ? v : "";
}

static bool file_is_regular(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* StaticFileRouter::sendStaticFileResponse() (no locations, no cache). */
static void send_static_file(const http_exchange *ex, wire_response *w, const char *file_path) {
    if (ex->method != M_GET) {
        wire_empty_html(w, 405);
        return;
    }
    struct stat st;
    char modified[64] = "";
    bool have_stat = false;
    const char *range = exchange_header(ex, "range");
    if (*range) {
        if (!file_stat(file_path, &st, modified, sizeof modified)) {
            wire_not_found_page(w);
            return;
        }
        have_stat = true;
        if (strcmp(exchange_header(ex, "if-modified-since"), modified) == 0) {
            w->status = 304;
            return;
        }
        const char *if_range = exchange_header(ex, "if-range");
        if (!*if_range || strcmp(if_range, modified) == 0) {
            uint64_t start = 0, end = 0, size = (uint64_t)st.st_size;
            switch (parse_range_header(range, size, &start, &end)) {
            case RANGE_SINGLE:
            case RANGE_MULTI:
                if (wire_file(w, file_path, start, end - start)) {
                    char content_range[128];
                    if (end - start < size) w->status = 206;
                    snprintf(content_range, sizeof content_range, "bytes %llu-%llu/%llu", (unsigned long long)start,
                             (unsigned long long)(end - 1), (unsigned long long)size);
                    wire_set_header(w, "Content-Range", content_range);
                    wire_set_header(w, "Last-Modified", modified);
                    wire_set_header(w, "Expires", "Thu, 01 Jan 1970 00:00:00 GMT");
                }
                return;
            case RANGE_NOT_SATISFIABLE: {
                char content_range[64];
                snprintf(content_range, sizeof content_range, "bytes */%llu", (unsigned long long)size);
                wire_empty_html(w, 416);
                wire_set_header(w, "Content-Range", content_range);
                return;
            }
            default:
                break;
            }
        }
    }
    if (!have_stat && !file_stat(file_path, &st, modified, sizeof modified)) {
        wire_not_found_page(w);
        return;
    }
    if (strcmp(exchange_header(ex, "if-modified-since"), modified) == 0) {
        w->status = 304;
        return;
    }
    const char *accept_encoding = exchange_header(ex, "accept-encoding");
    const char *encodings[][2] = {{"br", ".br"}, {"gzip", ".gz"}};
    bool served = false;
    for (size_t i = 0; i < 2 && !served; ++i) {
        if (!strstr(accept_encoding, encodings[i][0])) continue;
        char *compressed = sb_asprintf("%s%s", file_path, encodings[i][1]);
        if (file_is_regular(compressed)) {
            served = true;
            if (wire_file(w, compressed, 0, 0)) {
                sb_str_set(&w->content_type, drogon_mime_for(file_path));
                wire_set_header(w, "Content-Encoding", encodings[i][0]);
            }
        }
        free(compressed);
    }
    if (!served) wire_file(w, file_path, 0, 0);
    if (w->status != 404) {
        wire_set_header(w, "Last-Modified", modified);
        wire_set_header(w, "Expires", "Thu, 01 Jan 1970 00:00:00 GMT");
        wire_set_header(w, "accept-range", "bytes");
    }
}

/* StaticFileRouter::route() with Drogon's defaults: document root "./"
 * (the working directory), implicit page index.html, home page "/" ->
 * "/index.html", and only the default file types. */
void static_router(const http_exchange *ex, wire_response *w) {
    const char *path = strcmp(ex->path, "/") == 0 ? "/index.html" : ex->path;
    if (ex->path_has_nul) {
        wire_not_found_page(w);
        return;
    }
    if (strstr(path, "..")) {
        sb_strvec parts = sb_split(path, '/');
        int depth = 0;
        bool forbidden = false;
        for (size_t i = 0; i < parts.len && !forbidden; ++i) {
            if (!*parts.items[i]) continue;
            if (strcmp(parts.items[i], "..") == 0) --depth;
            else if (strcmp(parts.items[i], ".") != 0) ++depth;
            if (depth < 0) forbidden = true;
        }
        sb_strvec_free(&parts);
        if (forbidden) {
            wire_empty_html(w, 403);
            return;
        }
    }
    char *directory_path = sb_asprintf("./%s", path);
    struct stat st;
    if (stat(directory_path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            char *file_path = sb_asprintf("%s/index.html", directory_path);
            send_static_file(ex, w, file_path);
            free(file_path);
            free(directory_path);
            return;
        }
        const char *dot = strrchr(path, '.');
        if (!dot) {
            free(directory_path);
            wire_empty_html(w, 403);
            return;
        }
        char *extension = ascii_lower_dup(dot + 1, strlen(dot + 1));
        bool allowed = drogon_static_file_type(extension);
        free(extension);
        if (allowed) {
            send_static_file(ex, w, directory_path);
            free(directory_path);
            return;
        }
    }
    free(directory_path);
    wire_not_found_page(w);
}
