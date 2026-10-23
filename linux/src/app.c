#include "controller.h"
#include <fcntl.h>
#include <gio/gdesktopappinfo.h>
#include <glib-unix.h>
#include <gtk/gtk.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
typedef struct {
    GtkApplication* application;
    GtkWidget *window, *stack, *content, *profiles, *connect, *spinner, *message,
        *status, *mode, *identity;
    GtkWidget *up, *down, *total, *proxy, *groups, *subscriptions, *domains, *processes,
        *system_proxy, *refresh_interval;
    GtkWidget *probe_url, *probe_result, *offline_node, *storage, *retry;
    GtkListStore* connections;
    sbl_controller* controller;
    sbj* view;
    char *profiles_hash, *groups_hash, *data_dir, *runtime_dir, *pending_uri;
    bool busy, closing, updating, dialog_open;
    sbl_action active;
    unsigned poll_timer, sync_timer;
#ifdef SBL_UI_TEST
    int test_step, test_proxy, test_target;
    char* test_screenshot;
    bool test_mode, test_failed;
#endif
} app;
typedef struct {
    app* app;
    sbl_action action;
    char *id, *other;
    size_t index;
} binding;
static void render(app* a);
static void enroll_dialog(app* a, const char* server, const char* code);
static void shutdown_app(app* a);
static GtkWidget* label(const char* text, const char* class_name) {
    GtkWidget* widget = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(widget), 0);
    gtk_label_set_line_wrap(GTK_LABEL(widget), TRUE);
    if (class_name)
        gtk_style_context_add_class(gtk_widget_get_style_context(widget), class_name);
    return widget;
}
static GtkWidget* box(GtkOrientation direction, int spacing) {
    return gtk_box_new(direction, spacing);
}
static void pack(GtkWidget* container, GtkWidget* child) {
    gtk_box_pack_start(GTK_BOX(container), child, FALSE, FALSE, 0);
}
static GtkWidget* button(const char* text) {
    return gtk_button_new_with_label(text);
}
static GtkWidget* card(void) {
    GtkWidget* widget = box(GTK_ORIENTATION_VERTICAL, 12);
    gtk_style_context_add_class(gtk_widget_get_style_context(widget), "card");
    return widget;
}
static void clear_box(GtkWidget* widget) {
    GList* items = gtk_container_get_children(GTK_CONTAINER(widget));
    for (GList* p = items; p; p = p->next)
        gtk_widget_destroy(p->data);
    g_list_free(items);
}
static sbj* profile(app* a) {
    return sbl_profile(a->view, sbj_get_str(a->view, "selected_id", ""));
}
static bool running(app* a) {
    return sbj_get_bool(sbj_get(a->view, "runtime"), "running", false);
}
static void show_message(app* a, const char* message, bool error) {
    gtk_label_set_text(GTK_LABEL(a->message), message ? message : "");
    gtk_widget_set_visible(a->message, message && *message);
    GtkStyleContext* style = gtk_widget_get_style_context(a->message);
    if (error)
        gtk_style_context_add_class(style, "error");
    else
        gtk_style_context_remove_class(style, "error");
}
static bool submit(app* a, sbl_action action, const char* x, const char* y,
                   const char* z, int number) {
    if (a->closing && action != SBL_SHUTDOWN)
        return false;
    if (!sbl_controller_submit(a->controller, action, x, y, z, number))
        return false;
    a->busy = true;
    a->active = action;
    gtk_spinner_start(GTK_SPINNER(a->spinner));
    gtk_widget_set_sensitive(a->content, FALSE);
    gtk_widget_set_sensitive(a->profiles, FALSE);
    gtk_widget_set_sensitive(a->connect, action == SBL_CONNECT ||
                                             (running(a) && action != SBL_DISCONNECT &&
                                              action != SBL_SHUTDOWN));
    if (action == SBL_CONNECT)
        gtk_button_set_label(GTK_BUTTON(a->connect), "取消连接");
    if (action != SBL_STATUS && action != SBL_SYNC)
        show_message(a, "正在处理…", false);
    return true;
}
static void bind_free(gpointer data, GClosure* closure) {
    binding* b = data;
    free(b->id);
    free(b->other);
    free(b);
    (void)closure;
}
static binding* bind_new(app* a, sbl_action action, const char* id, const char* other,
                         size_t index) {
    binding* b = sb_xcalloc(1, sizeof *b);
    b->app = a;
    b->action = action;
    b->id = sb_strdup(id ? id : "");
    b->other = sb_strdup(other ? other : "");
    b->index = index;
    return b;
}
static bool confirm(app* a, const char* title, const char* detail) {
    a->dialog_open = true;
    GtkWidget* dialog = gtk_message_dialog_new(
        GTK_WINDOW(a->window), GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION, GTK_BUTTONS_NONE, "%s", title);
    gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(dialog), "%s", detail);
    gtk_dialog_add_buttons(GTK_DIALOG(dialog), "取消", GTK_RESPONSE_CANCEL, "确定",
                           GTK_RESPONSE_ACCEPT, NULL);
    bool ok = gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT;
    gtk_widget_destroy(dialog);
    a->dialog_open = false;
    return ok;
}
static GtkWidget* dialog_new(app* a, const char* title, const char* accept,
                             GtkWidget** content) {
    a->dialog_open = true;
    GtkWidget* dialog = gtk_dialog_new_with_buttons(
        title, GTK_WINDOW(a->window), GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "取消", GTK_RESPONSE_CANCEL, accept, GTK_RESPONSE_ACCEPT, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 520, -1);
    *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(*content), 22);
    gtk_box_set_spacing(GTK_BOX(*content), 12);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
    return dialog;
}
static GtkWidget* entry_field(GtkWidget* content, const char* title, const char* value,
                              bool secret) {
    pack(content, label(title, "field-label"));
    GtkWidget* entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(entry), value ? value : "");
    gtk_entry_set_visibility(GTK_ENTRY(entry), !secret);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    pack(content, entry);
    return entry;
}
static void action_button(GtkButton* widget, void* data) {
    binding* b = data;
    app* a = b->app;
    if (a->busy || a->closing)
        return;
    if (b->action == SBL_DELETE_PROFILE &&
        !confirm(a, "删除当前连接配置？",
                 "该配置的托管凭据、订阅与本地规则会从加密仓库中删除。"))
        return;
    if (b->action == SBL_REMOVE_SUBSCRIPTION &&
        !confirm(
            a, "删除这个订阅？",
            "引用其中节点的本地规则或默认选择需要先调整；正在连接时会验证剩余配置。"))
        return;
    if (b->action == SBL_DETACH &&
        !confirm(a, "脱离管理中心？",
                 "保留本地订阅，移除托管凭据、托管配置与路由设置。"))
        return;
    submit(a, b->action, b->id, b->other, NULL, 0);
    (void)widget;
}
static GtkWidget* action(app* a, const char* text, sbl_action act, const char* id) {
    GtkWidget* widget = button(text);
    g_signal_connect_data(widget, "clicked", G_CALLBACK(action_button),
                          bind_new(a, act, id, NULL, 0), bind_free, 0);
    return widget;
}
static void connection_clicked(GtkButton* widget, void* data) {
    app* a = data;
    if (a->busy) {
        if (a->active == SBL_CONNECT || running(a)) {
            sbl_controller_cancel(a->controller);
            show_message(a, "正在取消连接并清理网络状态…", false);
            submit(a, SBL_DISCONNECT, NULL, NULL, NULL, 0);
            gtk_widget_set_sensitive(a->connect, FALSE);
        }
        return;
    }
    submit(a, running(a) ? SBL_DISCONNECT : SBL_CONNECT, NULL, NULL, NULL,
           gtk_combo_box_get_active(GTK_COMBO_BOX(a->mode)));
    (void)widget;
}
static void profile_changed(GtkComboBox* widget, void* data) {
    app* a = data;
    if (a->updating || a->busy)
        return;
    const char* id = gtk_combo_box_get_active_id(widget);
    if (id && strcmp(id, sbj_get_str(a->view, "selected_id", "")))
        submit(a, SBL_SELECT_PROFILE, id, NULL, NULL, 0);
}
static void profile_name_dialog(GtkButton* widget, void* data) {
    binding* b = data;
    app* a = b->app;
    if (a->busy)
        return;
    GtkWidget* content;
    GtkWidget* dialog =
        dialog_new(a, b->action == SBL_NEW_PROFILE ? "新建独立连接" : "重命名连接",
                   "保存", &content);
    GtkWidget* entry = entry_field(
        content, "连接名称",
        b->action == SBL_NEW_PROFILE ? "" : sbj_get_str(profile(a), "name", ""), false);
    gtk_entry_set_max_length(GTK_ENTRY(entry), 128);
    gtk_widget_show_all(dialog);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT)
        submit(a, b->action, gtk_entry_get_text(GTK_ENTRY(entry)), NULL, NULL, 0);
    gtk_widget_destroy(dialog);
    a->dialog_open = false;
    (void)widget;
}
static GtkWidget* profile_name_button(app* a, const char* text, sbl_action action_id) {
    GtkWidget* widget = button(text);
    g_signal_connect_data(widget, "clicked", G_CALLBACK(profile_name_dialog),
                          bind_new(a, action_id, NULL, NULL, 0), bind_free, 0);
    return widget;
}
static void enroll_dialog(app* a, const char* server, const char* code) {
    if (a->busy || a->closing)
        return;
    GtkWidget* content;
    GtkWidget* dialog = dialog_new(a, "加入管理中心", "注册设备", &content);
    pack(content, label("使用中心生成的一次性设备注册码。已有本地订阅会保留，凭据只存入"
                        "系统钥匙串保护的加密仓库。",
                        "muted"));
    GtkWidget *address = entry_field(content, "管理中心 HTTPS 地址", server, false),
              *code_entry = entry_field(content, "一次性注册码", code, true);
    gtk_entry_set_placeholder_text(GTK_ENTRY(address), "https://panel.example.com");
    gtk_widget_show_all(dialog);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT)
        submit(a, SBL_ENROLL, gtk_entry_get_text(GTK_ENTRY(address)),
               gtk_entry_get_text(GTK_ENTRY(code_entry)), NULL, 0);
    gtk_entry_set_text(GTK_ENTRY(code_entry), "");
    gtk_widget_destroy(dialog);
    a->dialog_open = false;
}
static void enroll_clicked(GtkButton* widget, void* data) {
    enroll_dialog(data, "", "");
    (void)widget;
}
static void visible_link(GtkToggleButton* toggle, void* data) {
    gtk_entry_set_visibility(GTK_ENTRY(data), gtk_toggle_button_get_active(toggle));
}
static void subscription_dialog(GtkButton* widget, void* data) {
    binding* b = data;
    app* a = b->app;
    if (a->busy)
        return;
    GtkWidget* content;
    bool edit = b->action == SBL_EDIT_SUBSCRIPTION, remote = b->action != SBL_IMPORT;
    GtkWidget* dialog = dialog_new(a,
                                   edit     ? "编辑订阅"
                                   : remote ? "添加订阅地址"
                                            : "离线导入订阅",
                                   edit ? "保存" : "导入", &content);
    GtkWidget* name = entry_field(content, "订阅名称", edit ? b->other : "", false);
    gtk_entry_set_max_length(GTK_ENTRY(name), 128);
    GtkWidget *input = NULL, *offline = NULL;
    if (remote) {
        input = entry_field(content,
                            edit ? "新订阅地址（留空保留现有地址）" : "HTTPS 订阅地址",
                            "", true);
        GtkWidget* show = gtk_check_button_new_with_label("显示链接");
        g_signal_connect(show, "toggled", G_CALLBACK(visible_link), input);
        pack(content, show);
        if (edit) {
            offline = gtk_check_button_new_with_label("停止远程更新，保留现有节点");
            pack(content, offline);
        }
    } else {
        pack(content, label("粘贴代理链接、Base64 订阅、Clash YAML 或 sing-box "
                            "JSON。只导入节点，不执行脚本或导入远端规则。",
                            "muted"));
        GtkWidget* scroll = gtk_scrolled_window_new(NULL, NULL);
        gtk_widget_set_size_request(scroll, -1, 240);
        input = gtk_text_view_new();
        gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(input), GTK_WRAP_WORD_CHAR);
        gtk_container_add(GTK_CONTAINER(scroll), input);
        pack(content, scroll);
    }
    gtk_widget_show_all(dialog);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        if (remote)
            submit(a, b->action, edit ? b->id : gtk_entry_get_text(GTK_ENTRY(name)),
                   edit ? gtk_entry_get_text(GTK_ENTRY(name))
                        : gtk_entry_get_text(GTK_ENTRY(input)),
                   edit ? gtk_entry_get_text(GTK_ENTRY(input)) : NULL,
                   offline && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(offline)));
        else {
            GtkTextBuffer* buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(input));
            GtkTextIter start, end;
            gtk_text_buffer_get_bounds(buffer, &start, &end);
            char* raw = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
            submit(a, SBL_IMPORT, gtk_entry_get_text(GTK_ENTRY(name)), raw, NULL, 0);
            g_free(raw);
        }
    }
    if (remote)
        gtk_entry_set_text(GTK_ENTRY(input), "");
    gtk_widget_destroy(dialog);
    a->dialog_open = false;
    (void)widget;
}
static GtkWidget* subscription_button(app* a, const char* text, sbl_action act,
                                      const char* id, const char* name) {
    GtkWidget* widget = button(text);
    g_signal_connect_data(widget, "clicked", G_CALLBACK(subscription_dialog),
                          bind_new(a, act, id, name, 0), bind_free, 0);
    return widget;
}
static void import_file(GtkButton* widget, void* data) {
    app* a = data;
    if (a->busy)
        return;
    a->dialog_open = true;
    GtkWidget* dialog = gtk_file_chooser_dialog_new(
        "选择订阅文件", GTK_WINDOW(a->window), GTK_FILE_CHOOSER_ACTION_OPEN, "取消",
        GTK_RESPONSE_CANCEL, "导入", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_local_only(GTK_FILE_CHOOSER(dialog), TRUE);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char* path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        int fd = path ? open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK) : -1;
        struct stat st;
        if (fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size > 0 &&
            st.st_size <= 512 * 1024) {
            char* raw = sb_xmalloc((size_t)st.st_size + 1);
            size_t done = 0;
            while (done < (size_t)st.st_size) {
                ssize_t count = read(fd, raw + done, (size_t)st.st_size - done);
                if (count <= 0)
                    break;
                done += (size_t)count;
            }
            raw[done] = 0;
            char* name = g_path_get_basename(path);
            if (done == (size_t)st.st_size && !memchr(raw, 0, done))
                submit(a, SBL_IMPORT, name, raw, NULL, 0);
            else
                show_message(a, "无法完整读取订阅文件。", true);
            g_free(name);
            free(raw);
        } else
            show_message(a, "请选择不超过 512 KB 的普通文本文件。", true);
        if (fd >= 0)
            close(fd);
        g_free(path);
    }
    gtk_widget_destroy(dialog);
    a->dialog_open = false;
    (void)widget;
}
static GtkWidget* node_combo(app* a, bool include_direct) {
    GtkWidget* combo = gtk_combo_box_text_new();
    const sbj* nodes = sbj_get(profile(a), "nodes");
    for (size_t i = 0; i < sbj_arr_len(nodes); ++i) {
        const sbj* node = sbj_arr_at(nodes, i);
        if (!include_direct && sbj_string_is(sbj_get(node, "type"), "direct"))
            continue;
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo),
                                  sbj_get_str(node, "tag", ""),
                                  sbj_get_str(node, "name", ""));
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
    return combo;
}
static sbj* split_values(const char* text) {
    sbj* array = sbj_array();
    char** parts = g_strsplit_set(text, ",\n\r", -1);
    for (size_t i = 0; parts[i]; ++i) {
        g_strstrip(parts[i]);
        if (*parts[i])
            sbj_arr_push(array, sbj_str(parts[i]));
    }
    g_strfreev(parts);
    return array;
}
static void rule_dialog(GtkButton* widget, void* data) {
    binding* b = data;
    app* a = b->app;
    if (a->busy)
        return;
    bool process = b->index != 0;
    GtkWidget* content;
    GtkWidget* dialog =
        dialog_new(a, process ? "添加进程规则" : "添加域名分组", "保存规则", &content);
    GtkWidget *name = process ? NULL : entry_field(content, "分组名称", "", false),
              *kind = NULL;
    if (process) {
        pack(content, label("匹配方式", "field-label"));
        kind = gtk_combo_box_text_new();
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(kind), "process_name",
                                  "进程名称（例如 firefox）");
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(kind), "process_path",
                                  "完整可执行文件路径");
        gtk_combo_box_set_active(GTK_COMBO_BOX(kind), 0);
        pack(content, kind);
    }
    GtkWidget* values = entry_field(content,
                                    process ? "匹配值（多个值用逗号分隔）"
                                            : "域名后缀（小写，多个域名用逗号分隔）",
                                    "", false);
    pack(content, label("出口节点", "field-label"));
    GtkWidget* outbound = node_combo(a, true);
    pack(content, outbound);
    pack(content, label(process ? "进程规则优先于普通业务规则；私网、托管 WireGuard "
                                  "与精确域名规则保留优先级。"
                                : "域名不能互相覆盖。分组同时设置对应的 DNS 出口。",
                        "muted"));
    gtk_widget_show_all(dialog);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        const char* target = gtk_combo_box_get_active_id(GTK_COMBO_BOX(outbound));
        if (target) {
            sbj *settings = sbj_clone(sbj_get(profile(a), "settings")),
                *rule = sbj_object();
            sbj_set_str(rule, "outbound", target);
            sbj* list = split_values(gtk_entry_get_text(GTK_ENTRY(values)));
            if (process)
                sbj_set(rule, gtk_combo_box_get_active_id(GTK_COMBO_BOX(kind)), list);
            else {
                char* id = sbl_uuid();
                sbj_set_str(rule, "id", id);
                free(id);
                sbj_set_str(rule, "name", gtk_entry_get_text(GTK_ENTRY(name)));
                sbj_set(rule, "domains", list);
            }
            sbj_arr_push(
                sbj_get_or_array(settings, process ? "process_rules" : "local_groups"),
                rule);
            char* raw = sbj_dump(settings, -1);
            submit(a, SBL_SETTINGS, raw, NULL, NULL, 0);
            free(raw);
            sbj_free(settings);
        } else
            show_message(a, "请先导入至少一个节点。", true);
    }
    gtk_widget_destroy(dialog);
    a->dialog_open = false;
    (void)widget;
}
static void remove_rule(GtkButton* widget, void* data) {
    binding* b = data;
    app* a = b->app;
    if (a->busy)
        return;
    sbj* settings = sbj_clone(sbj_get(profile(a), "settings"));
    sbj* array = sbj_get(settings, b->id);
    if (b->index < sbj_arr_len(array))
        sbj_free(sbj_arr_take(array, b->index));
    char* raw = sbj_dump(settings, -1);
    submit(a, SBL_SETTINGS, raw, NULL, NULL, 0);
    free(raw);
    sbj_free(settings);
    (void)widget;
}
static void selection_changed(GtkComboBox* combo, void* data) {
    binding* b = data;
    app* a = b->app;
    if (a->updating || a->busy)
        return;
    const char* node = gtk_combo_box_get_active_id(combo);
    if (node)
        submit(a, SBL_SELECT_NODE, b->id, node, NULL, 0);
}
static void offline_changed(GtkComboBox* combo, void* data) {
    app* a = data;
    if (a->updating || a->busy)
        return;
    const char* node = gtk_combo_box_get_active_id(combo);
    if (node)
        submit(a, SBL_SELECT_NODE, SBL_DEFAULT, node, NULL, 0);
}
static void proxy_toggled(GtkToggleButton* toggle, void* data) {
    app* a = data;
    if (!a->updating && !a->busy)
        submit(a, SBL_PROXY_SETTING, NULL, NULL, NULL,
               gtk_toggle_button_get_active(toggle));
}
static void interval_changed(GtkComboBox* combo, void* data) {
    app* a = data;
    if (!a->updating && !a->busy) {
        const char* id = gtk_combo_box_get_active_id(combo);
        if (id)
            submit(a, SBL_REFRESH_INTERVAL, NULL, NULL, NULL, atoi(id));
    }
}
static void probe_clicked(GtkButton* widget, void* data) {
    app* a = data;
    if (!a->busy)
        submit(a, SBL_PROBE, gtk_entry_get_text(GTK_ENTRY(a->probe_url)), NULL, NULL,
               0);
    (void)widget;
}
static char* byte_string(int64_t bytes) {
    if (bytes < 1024)
        return sb_asprintf("%lld B", (long long)bytes);
    if (bytes < 1024 * 1024)
        return sb_asprintf("%.1f KB", (double)bytes / 1024);
    if (bytes < INT64_C(1024) * 1024 * 1024)
        return sb_asprintf("%.1f MB", (double)bytes / (1024 * 1024));
    return sb_asprintf("%.2f GB", (double)bytes / (1024 * 1024 * 1024));
}
static const char* friendly(app* a, const char* tag) {
    if (!strcmp(tag, SBL_DEFAULT))
        return "默认策略";
    if (!strcmp(tag, SBL_DIRECT))
        return "直接连接";
    if (!strcmp(tag, "GLOBAL"))
        return "全局策略";
    const sbj* nodes = sbj_get(profile(a), "nodes");
    for (size_t i = 0; i < sbj_arr_len(nodes); ++i) {
        const sbj* node = sbj_arr_at(nodes, i);
        if (sbj_string_is(sbj_get(node, "tag"), tag))
            return sbj_get_str(node, "name", tag);
    }
    return tag;
}
static char* friendly_chain(app* a, const sbj* chain) {
    GString* out = g_string_new(NULL);
    for (size_t i = 0; i < sbj_arr_len(chain); ++i) {
        if (i)
            g_string_append(out, " → ");
        g_string_append(out, friendly(a, sbj_as_str(sbj_arr_at(chain, i), "")));
    }
    char* text = sb_strdup(out->str);
    g_string_free(out, TRUE);
    return text;
}
static char* joined(const sbj* array) {
    GString* text = g_string_new(NULL);
    for (size_t i = 0; i < sbj_arr_len(array); ++i) {
        if (i)
            g_string_append(text, " · ");
        g_string_append(text, sbj_as_str(sbj_arr_at(array, i), ""));
    }
    char* out = sb_strdup(text->str);
    g_string_free(text, TRUE);
    return out;
}
static void render_subscriptions(app* a, const sbj* p) {
    clear_box(a->subscriptions);
    const sbj* subs = sbj_get(p, "subscriptions");
    if (!sbj_arr_len(subs)) {
        pack(a->subscriptions,
             label("还没有订阅。添加 HTTPS 地址，或离线导入已有节点即可独立连接。",
                   "empty"));
        return;
    }
    for (size_t i = 0; i < sbj_arr_len(subs); ++i) {
        const sbj* sub = sbj_arr_at(subs, i);
        const char *id = sbj_get_str(sub, "id", ""),
                   *name = sbj_get_str(sub, "name", "");
        GtkWidget *item = card(), *header = box(GTK_ORIENTATION_HORIZONTAL, 10),
                  *info = box(GTK_ORIENTATION_VERTICAL, 4);
        pack(info, label(name, "subtitle"));
        char* summary = sb_asprintf(
            "%lld 个节点 · %s", (long long)sbj_get_int(sub, "node_count", 0),
            sbj_get_bool(sub, "remote", false) ? "远程订阅" : "离线导入");
        pack(info, label(summary, "muted"));
        free(summary);
        gtk_box_pack_start(GTK_BOX(header), info, TRUE, TRUE, 0);
        if (sbj_get_bool(sub, "remote", false))
            pack(header, action(a, "刷新", SBL_REFRESH, id));
        pack(header, subscription_button(a, "编辑", SBL_EDIT_SUBSCRIPTION, id, name));
        pack(header, action(a, "删除", SBL_REMOVE_SUBSCRIPTION, id));
        pack(item, header);
        int64_t updated = sbj_get_int(sub, "updated_at", 0);
        GDateTime* date = updated ? g_date_time_new_from_unix_local(updated) : NULL;
        if (date) {
            char *time_text = g_date_time_format(date, "%Y-%m-%d %H:%M"),
                 *line = sb_asprintf("上次更新 %s", time_text);
            pack(item, label(line, "muted"));
            free(line);
            g_free(time_text);
            g_date_time_unref(date);
        }
        const sbj* metadata = sbj_get(sub, "metadata");
        if (sbj_get_bool(metadata, "available", false)) {
            char *used = byte_string(sbj_get_int(metadata, "used_bytes", 0)),
                 *total = byte_string(sbj_get_int(metadata, "total_bytes", 0));
            char* line = sb_asprintf("已用 %s / 套餐 %s", used, total);
            pack(item, label(line, "muted"));
            free(line);
            free(used);
            free(total);
            int64_t expiry =
                sbj_get_int(metadata, "expires_at", sbj_get_int(metadata, "expire", 0));
            if (expiry > 0) {
                date = g_date_time_new_from_unix_local(expiry);
                char* expiry_text = date ? g_date_time_format(date, "%Y-%m-%d") : NULL;
                line = sb_asprintf("%s %s",
                                   expiry < (int64_t)time(NULL) ? "已过期" : "有效期至",
                                   expiry_text ? expiry_text : "未知");
                pack(item,
                     label(line, expiry < (int64_t)time(NULL) ? "error" : "muted"));
                free(line);
                g_free(expiry_text);
                if (date)
                    g_date_time_unref(date);
            }
        }
        const sbj* report = sbj_get(sub, "report");
        int64_t skipped = sbj_get_int(report, "skipped", 0);
        if (skipped) {
            char* title = sb_asprintf("导入提示：跳过 %lld 项", (long long)skipped);
            GtkWidget* expander = gtk_expander_new(title);
            free(title);
            char* warnings = joined(sbj_get(report, "warnings"));
            gtk_container_add(GTK_CONTAINER(expander), label(warnings, "muted"));
            free(warnings);
            pack(item, expander);
        }
        if (*sbj_get_str(sub, "last_error", ""))
            pack(item, label(sbj_get_str(sub, "last_error", ""), "error"));
        pack(a->subscriptions, item);
    }
}
static void render_rules(app* a, const sbj* p, const char* key, GtkWidget* target) {
    clear_box(target);
    const sbj* rules = sbj_get(sbj_get(p, "settings"), key);
    if (!sbj_arr_len(rules)) {
        pack(target, label("暂无本地规则。", "muted"));
        return;
    }
    for (size_t i = 0; i < sbj_arr_len(rules); ++i) {
        const sbj* rule = sbj_arr_at(rules, i);
        const sbj* values = sbj_get(rule, "domains");
        if (!values)
            values = sbj_get(rule, "process_name");
        if (!values)
            values = sbj_get(rule, "process_path");
        char* values_text = joined(values);
        GtkWidget *row = box(GTK_ORIENTATION_HORIZONTAL, 12),
                  *text = box(GTK_ORIENTATION_VERTICAL, 4);
        if (sbj_get(rule, "name"))
            pack(text, label(sbj_get_str(rule, "name", ""), "field-label"));
        pack(text, label(values_text, NULL));
        free(values_text);
        pack(text, label(friendly(a, sbj_get_str(rule, "outbound", "")), "muted"));
        gtk_box_pack_start(GTK_BOX(row), text, TRUE, TRUE, 0);
        GtkWidget* remove = button("移除");
        g_signal_connect_data(remove, "clicked", G_CALLBACK(remove_rule),
                              bind_new(a, SBL_SETTINGS, key, NULL, i), bind_free, 0);
        pack(row, remove);
        pack(target, row);
    }
}
static void render_groups(app* a, const sbj* runtime) {
    const sbj* groups = sbj_get(sbj_get(runtime, "groups"), "proxies");
    char* hash = sbj_dump(groups, -1);
    if (a->groups_hash && !strcmp(a->groups_hash, hash)) {
        free(hash);
        return;
    }
    free(a->groups_hash);
    a->groups_hash = hash;
    clear_box(a->groups);
    bool any = false;
    for (size_t i = 0; i < sbj_obj_len(groups); ++i) {
        const char* tag = sbj_obj_key(groups, i);
        const sbj *group = sbj_obj_val(groups, i), *members = sbj_get(group, "all");
        if (!sbj_is_array(members))
            continue;
        any = true;
        GtkWidget *row = box(GTK_ORIENTATION_HORIZONTAL, 12),
                  *title = label(friendly(a, tag), "field-label");
        gtk_widget_set_size_request(title, 190, -1);
        pack(row, title);
        GtkWidget* combo = gtk_combo_box_text_new();
        for (size_t j = 0; j < sbj_arr_len(members); ++j) {
            const char* node = sbj_as_str(sbj_arr_at(members, j), "");
            gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), node,
                                      friendly(a, node));
        }
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo),
                                    sbj_get_str(group, "now", ""));
        gtk_widget_set_sensitive(combo,
                                 sbj_string_is(sbj_get(group, "type"), "Selector"));
        g_signal_connect_data(combo, "changed", G_CALLBACK(selection_changed),
                              bind_new(a, SBL_SELECT_NODE, tag, NULL, 0), bind_free, 0);
        gtk_box_pack_start(GTK_BOX(row), combo, TRUE, TRUE, 0);
        pack(row, action(a, "测速", SBL_DELAY, sbj_get_str(group, "now", "")));
        pack(a->groups, row);
    }
    if (!any)
        pack(a->groups, label(running(a) ? "当前配置没有可手动切换的策略组。"
                                         : "连接后显示核心中的真实策略组与当前节点。",
                              "muted"));
}
static void render_connections(app* a, const sbj* runtime) {
    gtk_list_store_clear(a->connections);
    const sbj* connections = sbj_get(sbj_get(runtime, "telemetry"), "connections");
    for (size_t i = 0; i < sbj_arr_len(connections) && i < 100; ++i) {
        const sbj *item = sbj_arr_at(connections, i),
                  *metadata = sbj_get(item, "metadata");
        const char* host = sbj_get_str(metadata, "host", "");
        if (!*host)
            host = sbj_get_str(metadata, "destinationIP", "");
        char *chain = friendly_chain(a, sbj_get(item, "chains")),
             *upload = byte_string(sbj_get_int(item, "upload", 0)),
             *download = byte_string(sbj_get_int(item, "download", 0));
        GtkTreeIter iter;
        gtk_list_store_append(a->connections, &iter);
        gtk_list_store_set(a->connections, &iter, 0, host, 1, chain, 2, upload, 3,
                           download, -1);
        free(chain);
        free(upload);
        free(download);
    }
}
static void render(app* a) {
    a->updating = true;
    gtk_widget_set_sensitive(a->mode, !running(a));
    bool opened = sbj_get_bool(a->view, "opened", false);
    const sbj *p = profile(a), *runtime = sbj_get(a->view, "runtime"),
              *telemetry = sbj_get(runtime, "telemetry");
    gtk_widget_set_sensitive(a->content, opened && !a->busy);
    gtk_widget_set_sensitive(a->profiles, opened && !a->busy);
    gtk_widget_set_sensitive(a->connect,
                             opened && (!a->busy || a->active == SBL_CONNECT ||
                                        (running(a) && a->active != SBL_DISCONNECT)));
    gtk_widget_set_visible(a->retry, !opened);
    gtk_button_set_label(GTK_BUTTON(a->connect), a->busy && a->active == SBL_CONNECT
                                                     ? "取消连接"
                                                 : running(a) ? "断开连接"
                                                              : "连接");
    gtk_label_set_text(GTK_LABEL(a->status), !opened      ? "等待解锁钥匙串"
                                             : running(a) ? "已连接"
                                                          : "未连接");
    gtk_label_set_text(GTK_LABEL(a->identity),
                       sbj_string_is(sbj_get(p, "mode"), "managed")
                           ? "托管连接 · 本地订阅可叠加"
                           : "独立连接 · 无需管理中心");
    char *up = byte_string(sbj_get_int(telemetry, "up", 0)),
         *down = byte_string(sbj_get_int(telemetry, "down", 0)),
         *total = byte_string(sbj_get_int(telemetry, "up_total", 0) +
                              sbj_get_int(telemetry, "down_total", 0));
    char *up_rate = sb_asprintf("%s/s", up), *down_rate = sb_asprintf("%s/s", down);
    gtk_label_set_text(GTK_LABEL(a->up), up_rate);
    gtk_label_set_text(GTK_LABEL(a->down), down_rate);
    gtk_label_set_text(GTK_LABEL(a->total), total);
    free(up);
    free(down);
    free(total);
    free(up_rate);
    free(down_rate);
    char* endpoint =
        running(a)
            ? (sbj_get_bool(runtime, "tun", false)
                   ? sb_strdup("TUN 已启用 · 当前用户流量")
                   : sb_asprintf("HTTP / SOCKS5 · 127.0.0.1:%lld · 需要认证",
                                 (long long)sbj_get_int(runtime, "proxy_port", 0)))
            : sb_strdup("连接后分配本机端口");
    gtk_label_set_text(GTK_LABEL(a->proxy), endpoint);
    free(endpoint);
    char *hash = sbj_dump(sbj_get(a->view, "profiles"), -1),
         *combined =
             sb_asprintf("%s/%s", sbj_get_str(a->view, "selected_id", ""), hash);
    free(hash);
    if (!a->profiles_hash || strcmp(a->profiles_hash, combined)) {
        free(a->profiles_hash);
        a->profiles_hash = combined;
        combined = NULL;
        gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(a->profiles));
        const sbj* profiles = sbj_get(a->view, "profiles");
        for (size_t i = 0; i < sbj_arr_len(profiles); ++i) {
            const sbj* item = sbj_arr_at(profiles, i);
            gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(a->profiles),
                                      sbj_get_str(item, "id", ""),
                                      sbj_get_str(item, "name", ""));
        }
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(a->profiles),
                                    sbj_get_str(a->view, "selected_id", ""));
        render_subscriptions(a, p);
        render_rules(a, p, "local_groups", a->domains);
        render_rules(a, p, "process_rules", a->processes);
        gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(a->offline_node));
        const sbj* nodes = sbj_get(p, "nodes");
        for (size_t i = 0; i < sbj_arr_len(nodes); ++i) {
            const sbj* node = sbj_arr_at(nodes, i);
            if (!sbj_string_is(sbj_get(node, "type"), "direct"))
                gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(a->offline_node),
                                          sbj_get_str(node, "tag", ""),
                                          sbj_get_str(node, "name", ""));
        }
        const char* choice = sbj_get_str(
            sbj_get(sbj_get(p, "settings"), "selector_choices"), SBL_DEFAULT, "");
        if (*choice)
            gtk_combo_box_set_active_id(GTK_COMBO_BOX(a->offline_node), choice);
        else
            gtk_combo_box_set_active(GTK_COMBO_BOX(a->offline_node), 0);
        gtk_widget_set_sensitive(a->offline_node,
                                 sbj_string_is(sbj_get(p, "mode"), "independent"));
        char interval[32];
        snprintf(interval, sizeof interval, "%lld",
                 (long long)sbj_get_int(p, "refresh_minutes", 360));
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(a->refresh_interval), interval);
    }
    free(combined);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(a->system_proxy),
                                 sbj_get_bool(a->view, "system_proxy", false));
    gtk_widget_set_sensitive(a->system_proxy,
                             sbj_get_bool(a->view, "system_proxy_available", false));
    render_groups(a, runtime);
    render_connections(a, runtime);
    gtk_widget_show_all(a->subscriptions);
    gtk_widget_show_all(a->domains);
    gtk_widget_show_all(a->processes);
    gtk_widget_show_all(a->groups);
    a->updating = false;
}
static GtkWidget* page(app* a, const char* id, const char* title,
                       const char* description) {
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL),
              *content = box(GTK_ORIENTATION_VERTICAL, 18);
    gtk_container_set_border_width(GTK_CONTAINER(content), 28);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_NEVER,
                                   GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll), content);
    pack(content, label(title, "page-title"));
    if (description)
        pack(content, label(description, "muted"));
    gtk_stack_add_named(GTK_STACK(a->stack), scroll, id);
    return content;
}
static void navigate(GtkButton* widget, void* data) {
    binding* b = data;
    gtk_stack_set_visible_child_name(GTK_STACK(b->app->stack), b->id);
    (void)widget;
}
static void retry_clicked(GtkButton* widget, void* data) {
    app* a = data;
    if (!a->busy)
        submit(a, SBL_OPEN, NULL, NULL, NULL, 0);
    (void)widget;
}
static void software_clicked(GtkButton* widget, void* data) {
    app* a = data;
    GDesktopAppInfo* software = g_desktop_app_info_new("org.gnome.Software.desktop");
    if (!software)
        software = g_desktop_app_info_new("org.kde.discover.desktop");
    if (!software || !g_app_info_launch(G_APP_INFO(software), NULL, NULL, NULL))
        show_message(a,
                     "请使用系统软件管理器更新 sb-easy-desktop。更新来源必须是已配置 "
                     "Signed-By 的可信软件仓库。",
                     false);
    if (software)
        g_object_unref(software);
    (void)widget;
}
static gboolean close_window(GtkWidget* widget, GdkEvent* event, void* data) {
    shutdown_app(data);
    (void)widget;
    (void)event;
    return TRUE;
}
static gboolean signal_close(void* data) {
    shutdown_app(data);
    return G_SOURCE_REMOVE;
}
static void build_window(app* a) {
    a->window = gtk_application_window_new(a->application);
    gtk_window_set_title(GTK_WINDOW(a->window), "sb-easy");
    gtk_window_set_default_size(GTK_WINDOW(a->window), 1180, 800);
    GtkWidget* header = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), "sb-easy");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(header), "Linux 桌面客户端");
    gtk_window_set_titlebar(GTK_WINDOW(a->window), header);
    a->profiles = gtk_combo_box_text_new();
    gtk_widget_set_size_request(a->profiles, 220, -1);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), a->profiles);
    g_signal_connect(a->profiles, "changed", G_CALLBACK(profile_changed), a);
    a->connect = button("连接");
    gtk_style_context_add_class(gtk_widget_get_style_context(a->connect),
                                "suggested-action");
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), a->connect);
    g_signal_connect(a->connect, "clicked", G_CALLBACK(connection_clicked), a);
    a->spinner = gtk_spinner_new();
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), a->spinner);
    GtkWidget *root = box(GTK_ORIENTATION_HORIZONTAL, 0),
              *sidebar = box(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_size_request(sidebar, 205, -1);
    gtk_container_set_border_width(GTK_CONTAINER(sidebar), 20);
    gtk_style_context_add_class(gtk_widget_get_style_context(sidebar), "sidebar");
    pack(sidebar, label("SB / EASY", "brand"));
    pack(sidebar, label("连接，由你掌控", "muted"));
    GtkWidget* gap = label("", NULL);
    gtk_widget_set_size_request(gap, -1, 24);
    pack(sidebar, gap);
    const char *ids[] = {"connection", "subscriptions", "routing", "diagnostics",
                         "settings"},
               *titles[] = {"连接概览", "订阅与节点", "本地路由", "连接诊断",
                            "设置与身份"};
    for (size_t i = 0; i < G_N_ELEMENTS(ids); ++i) {
        GtkWidget* nav = button(titles[i]);
        gtk_style_context_add_class(gtk_widget_get_style_context(nav), "nav");
        g_signal_connect_data(nav, "clicked", G_CALLBACK(navigate),
                              bind_new(a, SBL_STATUS, ids[i], NULL, 0), bind_free, 0);
        pack(sidebar, nav);
    }
    GtkWidget* spacer = box(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(sidebar), spacer, TRUE, TRUE, 0);
    pack(sidebar, label("凭据保存在加密仓库\n由系统钥匙串保护", "muted"));
    pack(root, sidebar);
    GtkWidget* right = box(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(root), right, TRUE, TRUE, 0);
    a->message = label("正在打开加密仓库…", "banner");
    pack(right, a->message);
    a->retry = button("解锁钥匙串后重试");
    g_signal_connect(a->retry, "clicked", G_CALLBACK(retry_clicked), a);
    pack(right, a->retry);
    a->stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(a->stack),
                                  GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    a->content = a->stack;
    gtk_box_pack_start(GTK_BOX(right), a->stack, TRUE, TRUE, 0);
    gtk_container_add(GTK_CONTAINER(a->window), root);
    GtkWidget *content =
                  page(a, "connection", "你的网络连接",
                       "在独立模式导入订阅即可连接，也可以加入管理中心接收托管配置。"),
              *hero = card();
    a->status = label("未连接", "hero");
    pack(hero, a->status);
    a->identity = label("独立连接 · 无需管理中心", "muted");
    pack(hero, a->identity);
    GtkWidget* mode_row = box(GTK_ORIENTATION_HORIZONTAL, 12);
    pack(mode_row, label("连接方式", "field-label"));
    a->mode = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->mode),
                                   "本机代理 · 无需管理员");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->mode), "TUN · 管理员授权");
    gtk_combo_box_set_active(GTK_COMBO_BOX(a->mode), 0);
    pack(mode_row, a->mode);
    pack(hero, mode_row);
    a->proxy = label("连接后分配本机端口", "muted");
    pack(hero, a->proxy);
    pack(hero, action(a, "复制认证代理地址", SBL_COPY_PROXY, NULL));
    pack(content, hero);
    GtkWidget* stats = box(GTK_ORIENTATION_HORIZONTAL, 14);
    GtkWidget** values[] = {&a->up, &a->down, &a->total};
    const char* names[] = {"上传速率", "下载速率", "累计流量"};
    for (size_t i = 0; i < G_N_ELEMENTS(values); ++i) {
        GtkWidget* item = card();
        pack(item, label(names[i], "muted"));
        *values[i] = label("0 B", "stat");
        pack(item, *values[i]);
        gtk_box_pack_start(GTK_BOX(stats), item, TRUE, TRUE, 0);
    }
    pack(content, stats);
    GtkWidget* default_card = card();
    pack(default_card, label("独立模式默认节点", "subtitle"));
    a->offline_node = gtk_combo_box_text_new();
    g_signal_connect(a->offline_node, "changed", G_CALLBACK(offline_changed), a);
    pack(default_card, a->offline_node);
    pack(content, default_card);
    GtkWidget* group_card = card();
    pack(group_card, label("实时策略组", "subtitle"));
    a->groups = box(GTK_ORIENTATION_VERTICAL, 10);
    pack(group_card, a->groups);
    pack(content, group_card);
    content = page(
        a, "subscriptions", "订阅与节点",
        "订阅地址、节点凭据与导入结果保存在本机加密仓库。失败的刷新会保留原有节点。");
    GtkWidget* toolbar = box(GTK_ORIENTATION_HORIZONTAL, 8);
    pack(toolbar, subscription_button(a, "添加订阅地址", SBL_ADD_URL, NULL, NULL));
    pack(toolbar, subscription_button(a, "粘贴导入", SBL_IMPORT, NULL, NULL));
    GtkWidget* file = button("从文件导入");
    g_signal_connect(file, "clicked", G_CALLBACK(import_file), a);
    pack(toolbar, file);
    pack(toolbar, action(a, "刷新全部", SBL_REFRESH, NULL));
    pack(content, toolbar);
    a->subscriptions = box(GTK_ORIENTATION_VERTICAL, 16);
    pack(content, a->subscriptions);
    content = page(a, "routing", "本地路由",
                   "先保留私网、托管 WireGuard "
                   "与精确域名规则，再应用本地分组；普通业务规则随后匹配。");
    GtkWidget *domain_card = card(),
              *domain_header = box(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(domain_header), label("域名分组", "subtitle"), TRUE,
                       TRUE, 0);
    GtkWidget* add = button("添加域名分组");
    g_signal_connect_data(add, "clicked", G_CALLBACK(rule_dialog),
                          bind_new(a, SBL_SETTINGS, NULL, NULL, 0), bind_free, 0);
    pack(domain_header, add);
    pack(domain_card, domain_header);
    a->domains = box(GTK_ORIENTATION_VERTICAL, 16);
    pack(domain_card, a->domains);
    pack(content, domain_card);
    GtkWidget *process_card = card(),
              *process_header = box(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(process_header), label("应用与进程", "subtitle"), TRUE,
                       TRUE, 0);
    add = button("添加进程规则");
    g_signal_connect_data(add, "clicked", G_CALLBACK(rule_dialog),
                          bind_new(a, SBL_SETTINGS, NULL, NULL, 1), bind_free, 0);
    pack(process_header, add);
    pack(process_card, process_header);
    pack(process_card,
         label("TUN 可识别当前用户的进程；本机代理模式取决于系统提供的进程信息。",
               "muted"));
    a->processes = box(GTK_ORIENTATION_VERTICAL, 16);
    pack(process_card, a->processes);
    pack(content, process_card);
    content = page(
        a, "diagnostics", "连接诊断",
        "通过当前核心发送真实 HTTP "
        "请求，并用本次连接的源端口匹配实际路由。快速结束的连接可能无法观测路由。");
    GtkWidget *probe_card = card(), *probe_row = box(GTK_ORIENTATION_HORIZONTAL, 10);
    a->probe_url = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(a->probe_url), "https://www.gstatic.com/generate_204");
    gtk_box_pack_start(GTK_BOX(probe_row), a->probe_url, TRUE, TRUE, 0);
    GtkWidget* probe = button("测试请求");
    g_signal_connect(probe, "clicked", G_CALLBACK(probe_clicked), a);
    pack(probe_row, probe);
    pack(probe_card, probe_row);
    a->probe_result = label("尚未运行诊断。", "mono");
    gtk_label_set_selectable(GTK_LABEL(a->probe_result), TRUE);
    pack(probe_card, a->probe_result);
    pack(content, probe_card);
    pack(content, label("实时连接（最多显示 100 条）", "subtitle"));
    a->connections = gtk_list_store_new(4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                                        G_TYPE_STRING);
    GtkWidget* tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(a->connections));
    const char* columns[] = {"目标", "实际出口链", "上传", "下载"};
    for (int i = 0; i < 4; ++i) {
        GtkCellRenderer* renderer = gtk_cell_renderer_text_new();
        GtkTreeViewColumn* column = gtk_tree_view_column_new_with_attributes(
            columns[i], renderer, "text", i, NULL);
        gtk_tree_view_column_set_resizable(column, TRUE);
        gtk_tree_view_append_column(GTK_TREE_VIEW(tree), column);
    }
    GtkWidget* tree_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(tree_scroll, -1, 280);
    gtk_container_add(GTK_CONTAINER(tree_scroll), tree);
    pack(content, tree_scroll);
    content = page(a, "settings", "设置与身份",
                   "独立配置与托管配置可分别保存。关闭窗口会断开连接，并恢复本应用更改"
                   "过的系统代理设置。");
    GtkWidget *identity_card = card(),
              *identity_buttons = box(GTK_ORIENTATION_HORIZONTAL, 8);
    pack(identity_card, label("连接配置", "subtitle"));
    pack(identity_buttons, profile_name_button(a, "新建", SBL_NEW_PROFILE));
    pack(identity_buttons, profile_name_button(a, "重命名", SBL_RENAME_PROFILE));
    pack(identity_buttons, action(a, "删除", SBL_DELETE_PROFILE, NULL));
    pack(identity_card, identity_buttons);
    GtkWidget *management = box(GTK_ORIENTATION_HORIZONTAL, 8),
              *enroll = button("加入管理中心");
    g_signal_connect(enroll, "clicked", G_CALLBACK(enroll_clicked), a);
    pack(management, enroll);
    pack(management, action(a, "同步配置", SBL_SYNC, NULL));
    pack(management, action(a, "脱离管理中心", SBL_DETACH, NULL));
    pack(identity_card, management);
    pack(content, identity_card);
    GtkWidget* network = card();
    pack(network, label("网络与订阅", "subtitle"));
    a->system_proxy = gtk_check_button_new_with_label(
        "连接本机代理时，设置 GNOME HTTP / HTTPS 系统代理");
    g_signal_connect(a->system_proxy, "toggled", G_CALLBACK(proxy_toggled), a);
    pack(network, a->system_proxy);
    pack(network, label("使用其他桌面环境时可手动配置带认证的本机代理，或启用 "
                        "TUN。断开时只恢复仍由本应用持有的设置。",
                        "muted"));
    pack(network, label("自动刷新订阅（应用打开时）", "field-label"));
    a->refresh_interval = gtk_combo_box_text_new();
    const char *intervals[] = {"0", "60", "360", "1440"},
               *interval_titles[] = {"关闭", "每小时", "每 6 小时", "每天"};
    for (size_t i = 0; i < 4; ++i)
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(a->refresh_interval), intervals[i],
                                  interval_titles[i]);
    g_signal_connect(a->refresh_interval, "changed", G_CALLBACK(interval_changed), a);
    pack(network, a->refresh_interval);
    pack(content, network);
    GtkWidget* security = card();
    pack(security, label("数据与更新", "subtitle"));
    a->storage = label("", "mono");
    gtk_label_set_selectable(GTK_LABEL(a->storage), TRUE);
    pack(security, a->storage);
    pack(security, label("版本 " SBL_VERSION " · "
                         "核心由构建时固定版本提供\n更新由系统包管理器验证仓"
                         "库签名；不执行配置中指定的程序。",
                         "muted"));
    GtkWidget* software = button("打开系统软件管理器");
    g_signal_connect(software, "clicked", G_CALLBACK(software_clicked), a);
    pack(security, software);
    pack(content, security);
    g_signal_connect(a->window, "delete-event", G_CALLBACK(close_window), a);
    gtk_stack_set_visible_child_name(GTK_STACK(a->stack), "connection");
    gtk_widget_show_all(a->window);
    gtk_widget_hide(a->retry);
}
static void result_text(app* a, sbl_event* event) {
    if (event->action == SBL_CONNECT && sbj_get_bool(event->result, "fallback", false))
        show_message(a, "更新后的配置无法启动，已恢复最后成功运行的配置。", false);
    if (event->action == SBL_PROBE && event->result) {
        char* chain = friendly_chain(a, sbj_get(event->result, "chains"));
        char* text = sb_asprintf(
            "%s  ·  HTTP %lld  ·  %lld ms\n%s\n规则：%s %s",
            sbj_get_bool(event->result, "success", false) ? "请求成功" : "请求未成功",
            (long long)sbj_get_int(event->result, "http_status", 0),
            (long long)sbj_get_int(event->result, "elapsed_ms", 0),
            sbj_get_bool(event->result, "route_observed", false)
                ? chain
                : "本次连接结束前未捕获路由证据",
            sbj_get_str(event->result, "rule", "不可用"),
            sbj_get_str(event->result, "rulePayload", ""));
        gtk_label_set_text(GTK_LABEL(a->probe_result), text);
        free(text);
        free(chain);
    } else if (event->action == SBL_DELAY && event->result) {
        GString* message = g_string_new(NULL);
        for (size_t i = 0; i < sbj_obj_len(event->result); ++i) {
            const sbj* value = sbj_obj_val(event->result, i);
            g_string_append_printf(message, "%s：",
                                   friendly(a, sbj_obj_key(event->result, i)));
            if (sbj_is_number(value))
                g_string_append_printf(message, "%lld ms",
                                       (long long)sbj_as_int(value, 0));
            else
                g_string_append(message, "超时 / 不可用");
        }
        show_message(a, message->str, false);
        g_string_free(message, TRUE);
    } else if (event->action == SBL_COPY_PROXY && event->result) {
        gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD),
                               sbj_get_str(event->result, "clipboard", ""), -1);
        show_message(
            a, "已复制带认证的本机代理地址；请只粘贴到你信任的应用。断开后该地址失效。",
            false);
    }
}
#ifdef SBL_UI_TEST
static gboolean test_continue(void* data);
#endif
static void event_received(sbl_event* event, void* data) {
    app* a = data;
    a->busy = event->pending;
    if (!a->busy)
        gtk_spinner_stop(GTK_SPINNER(a->spinner));
    sbj_free(a->view);
    a->view = event->view;
    event->view = NULL;
    if (event->action == SBL_SHUTDOWN) {
        sbl_event_free(event);
        g_application_quit(G_APPLICATION(a->application));
        return;
    }
    if (a->closing) {
        sbl_event_free(event);
        return;
    }
    render(a);
    if (!event->success)
        show_message(a, event->message, true);
    else if (event->action != SBL_STATUS && event->action != SBL_SYNC)
        show_message(a,
                     event->action == SBL_ENROLL
                         ? "设备身份已加密保存。点击同步配置以获取托管规则。"
                         : "",
                     false);
    result_text(a, event);
#ifdef SBL_UI_TEST
    if (a->test_mode) {
        if (!event->success ||
            (event->action == SBL_PROBE &&
             (!sbj_get_bool(event->result, "success", false) ||
              !sbj_get_bool(event->result, "route_observed", false)))) {
            a->test_failed = true;
            fprintf(stderr, "GTK smoke action %d failed: %s\n", event->action,
                    event->message);
            shutdown_app(a);
        } else
            g_timeout_add(100, test_continue, a);
    }
#endif
    if (a->pending_uri && event->success && !a->dialog_open) {
        char* uri = a->pending_uri;
        a->pending_uri = NULL;
        GUri* parsed = g_uri_parse(uri, G_URI_FLAGS_NONE, NULL);
        const char* query = parsed ? g_uri_get_query(parsed) : NULL;
        GHashTable* params =
            query ? g_uri_parse_params(query, -1, "&", G_URI_PARAMS_NONE, NULL) : NULL;
        if (params) {
            enroll_dialog(a, g_hash_table_lookup(params, "server"),
                          g_hash_table_lookup(params, "code"));
            g_hash_table_unref(params);
        }
        if (parsed)
            g_uri_unref(parsed);
        free(uri);
    }
    sbl_event_free(event);
}
static gboolean poll(void* data) {
    app* a = data;
    if (!a->busy && !a->closing && !a->dialog_open &&
        sbj_get_bool(a->view, "opened", false) && running(a))
        submit(a, SBL_STATUS, NULL, NULL, NULL, 0);
    return G_SOURCE_CONTINUE;
}
static gboolean synchronize(void* data) {
    app* a = data;
    if (a->busy || a->closing || a->dialog_open ||
        !sbj_get_bool(a->view, "opened", false))
        return G_SOURCE_CONTINUE;
    const sbj *p = profile(a), *subs = sbj_get(p, "subscriptions");
    bool useful = sbj_string_is(sbj_get(p, "mode"), "managed");
    if (sbj_get_int(p, "refresh_minutes", 360))
        for (size_t i = 0; i < sbj_arr_len(subs); ++i)
            if (sbj_get_bool(sbj_arr_at(subs, i), "remote", false))
                useful = true;
    if (useful)
        submit(a, SBL_SYNC, NULL, NULL, NULL, 1);
    return G_SOURCE_CONTINUE;
}
static void shutdown_app(app* a) {
    if (a->closing)
        return;
    a->closing = true;
    if (a->poll_timer) {
        g_source_remove(a->poll_timer);
        a->poll_timer = 0;
    }
    if (a->sync_timer) {
        g_source_remove(a->sync_timer);
        a->sync_timer = 0;
    }
    sbl_controller_cancel(a->controller);
    show_message(a, "正在断开并恢复系统代理…", false);
    gtk_widget_set_sensitive(a->content, FALSE);
    gtk_widget_set_sensitive(a->connect, FALSE);
    submit(a, SBL_SHUTDOWN, NULL, NULL, NULL, 0);
}
static void activate(GtkApplication* application, void* data) {
    app* a = data;
    if (a->window) {
        gtk_window_present(GTK_WINDOW(a->window));
        return;
    }
    build_window(a);
    gtk_label_set_text(GTK_LABEL(a->storage), a->data_dir);
    unsigned char test_key[32];
    const unsigned char* key = NULL;
    bool session_test = false;
#ifdef SBL_UI_TEST
    if (a->test_mode) {
        memset(test_key, 77, sizeof test_key);
        key = test_key;
        session_test = true;
    }
#else
    (void)test_key;
#endif
    a->controller = sbl_controller_new(a->data_dir, a->runtime_dir, key, session_test,
                                       event_received, a);
    submit(a, SBL_OPEN, NULL, NULL, NULL, 0);
#ifdef SBL_UI_TEST
    if (!a->test_mode)
#endif
    {
        a->poll_timer = g_timeout_add_seconds(2, poll, a);
        a->sync_timer = g_timeout_add_seconds(60, synchronize, a);
    }
    g_unix_signal_add(SIGTERM, signal_close, a);
    g_unix_signal_add(SIGINT, signal_close, a);
    (void)application;
}
static void open_files(GApplication* application, GFile** files, int count,
                       const char* hint, void* data) {
    app* a = data;
    for (int i = 0; i < count; ++i) {
        char* uri = g_file_get_uri(files[i]);
        GUri* parsed = uri && strlen(uri) <= 8192
                           ? g_uri_parse(uri, G_URI_FLAGS_NONE, NULL)
                           : NULL;
        if (parsed && !g_strcmp0(g_uri_get_scheme(parsed), "sbeasy") &&
            !g_strcmp0(g_uri_get_host(parsed), "enroll")) {
            free(a->pending_uri);
            a->pending_uri = sb_strdup(uri);
        }
        if (parsed)
            g_uri_unref(parsed);
        g_free(uri);
    }
    activate(GTK_APPLICATION(application), a);
    if (a->pending_uri && sbj_get_bool(a->view, "opened", false) && !a->busy) {
        GUri* parsed = g_uri_parse(a->pending_uri, G_URI_FLAGS_NONE, NULL);
        const char* query = parsed ? g_uri_get_query(parsed) : NULL;
        GHashTable* params =
            query ? g_uri_parse_params(query, -1, "&", G_URI_PARAMS_NONE, NULL) : NULL;
        if (params) {
            enroll_dialog(a, g_hash_table_lookup(params, "server"),
                          g_hash_table_lookup(params, "code"));
            g_hash_table_unref(params);
        }
        if (parsed)
            g_uri_unref(parsed);
        free(a->pending_uri);
        a->pending_uri = NULL;
    }
    (void)hint;
}
#ifdef SBL_UI_TEST
static gboolean test_continue(void* data) {
    app* a = data;
    if (a->closing || a->busy)
        return G_SOURCE_REMOVE;
    switch (a->test_step++) {
    case 0: {
        char* body =
            sb_asprintf("{\"outbounds\":[{\"type\":\"http\",\"tag\":\"Local acceptance "
                        "node\",\"server\":\"127.0.0.1\",\"server_port\":%d}]}",
                        a->test_proxy);
        submit(a, SBL_IMPORT, "离线测试订阅", body, NULL, 0);
        free(body);
        break;
    }
    case 1:
        gtk_button_clicked(GTK_BUTTON(a->connect));
        break;
    case 2: {
        char* url = sb_asprintf("http://127.0.0.1:%d/slow", a->test_target);
        gtk_entry_set_text(GTK_ENTRY(a->probe_url), url);
        submit(a, SBL_PROBE, url, NULL, NULL, 0);
        free(url);
        break;
    }
    case 3: {
        gtk_stack_set_visible_child_name(GTK_STACK(a->stack), "connection");
        g_timeout_add(300, test_continue, a);
        break;
    }
    case 4: {
        GdkWindow* window = gtk_widget_get_window(a->window);
        int width = gdk_window_get_width(window),
            height = gdk_window_get_height(window);
        GdkPixbuf* image = gdk_pixbuf_get_from_window(window, 0, 0, width, height);
        if (!image || !gdk_pixbuf_save(image, a->test_screenshot, "png", NULL, NULL))
            a->test_failed = true;
        if (image)
            g_object_unref(image);
        gtk_button_clicked(GTK_BUTTON(a->connect));
        break;
    }
    default:
        shutdown_app(a);
        break;
    }
    return G_SOURCE_REMOVE;
}
#endif
int main(int argc, char** argv) {
    umask(0077);
    if (geteuid() == 0) {
        fputs("Run the desktop as your normal user; TUN uses the authorized system "
              "service.\n",
              stderr);
        return 2;
    }
    app a = {0};
    const char* runtime = g_getenv("XDG_RUNTIME_DIR");
#ifdef SBL_UI_TEST
    if (argc == 6 && !strcmp(argv[1], "--self-test")) {
        a.test_mode = true;
        a.data_dir = sb_asprintf("%s/data", argv[2]);
        a.runtime_dir = sb_asprintf("%s/runtime", argv[2]);
        a.test_proxy = atoi(argv[3]);
        a.test_target = atoi(argv[4]);
        a.test_screenshot = sb_strdup(argv[5]);
        argc = 1;
    }
#endif
    if (!a.data_dir)
        a.data_dir = g_build_filename(g_get_user_data_dir(), "sb-easy-desktop", NULL);
    if (argc == 2 && !strcmp(argv[1], "--recover-proxy")) {
        sb_err err = {0};
        int rc = sbl_proxy_restore(a.data_dir, &err);
        if (rc)
            fprintf(stderr, "%s\n", err.msg);
        free(a.data_dir);
        return rc != 0;
    }
    if (!a.runtime_dir) {
        sb_err err = {0};
        if (!runtime || sbl_private_dir(runtime, geteuid(), &err)) {
            fputs("A private XDG_RUNTIME_DIR is required. Start sb-easy from your "
                  "desktop session.\n",
                  stderr);
            free(a.data_dir);
            return 2;
        }
        a.runtime_dir = g_build_filename(runtime, "sb-easy-desktop", NULL);
    }
    a.application = gtk_application_new(SBL_APP_ID, G_APPLICATION_HANDLES_OPEN);
    g_signal_connect(a.application, "activate", G_CALLBACK(activate), &a);
    g_signal_connect(a.application, "open", G_CALLBACK(open_files), &a);
    gtk_init(NULL, NULL);
    GtkCssProvider* css = gtk_css_provider_new();
    const char* style =
        "window{background:#f3f6f8;color:#162b38;} "
        "headerbar{background:#fff;border-bottom:1px solid #dae2e7;} "
        ".sidebar{background:#122e3a;color:#f4fafc;} .sidebar .muted{color:#9fb8c4;} "
        ".brand{font-size:24px;font-weight:800;color:#67e4ce;} "
        ".nav{background:transparent;background-image:none;color:#e4eff3;border:none;"
        "box-shadow:none;padding:12px;font-weight:600;} "
        ".nav:hover{background:#204454;} .page-title{font-size:30px;font-weight:700;} "
        ".hero{font-size:42px;font-weight:700;color:#087c72;} "
        ".subtitle{font-size:18px;font-weight:700;} "
        ".muted{color:#627985;font-size:13px;} .field-label{font-weight:600;} "
        ".card{background:white;border:1px solid "
        "#dae4e9;border-radius:12px;padding:22px;} "
        ".stat{font-size:25px;font-weight:700;} .banner{padding:12px "
        "28px;background:#e2f4f0;color:#176f62;} .error{color:#a43232;} "
        ".banner.error{background:#fbe8e7;} "
        ".mono{font-family:monospace;font-size:12px;} "
        ".empty{padding:32px;color:#627985;} button{padding:8px "
        "13px;border-radius:7px;} "
        "button.suggested-action{background:#087e74;background-image:none;color:white;"
        "border-color:#087e74;} entry,combobox{min-height:30px;}";
    gtk_css_provider_load_from_data(css, style, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
                                              GTK_STYLE_PROVIDER(css),
                                              GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);
    int code = g_application_run(G_APPLICATION(a.application), argc, argv);
    if (a.controller)
        sbl_controller_free(a.controller);
    if (a.connections)
        g_object_unref(a.connections);
    g_object_unref(a.application);
    sbj_free(a.view);
    free(a.profiles_hash);
    free(a.groups_hash);
    free(a.data_dir);
    free(a.runtime_dir);
    free(a.pending_uri);
#ifdef SBL_UI_TEST
    if (a.test_mode && a.test_failed)
        code = 1;
    free(a.test_screenshot);
#endif
    return code;
}
