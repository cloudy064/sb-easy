import SwiftUI

@main struct SBEasyApp: App {
    @StateObject private var model = VPNController()
    var body: some Scene {
        WindowGroup {
            Dashboard(model: model)
                .onOpenURL { url in NotificationCenter.default.post(name: .enrollmentLink, object: url.absoluteString) }
        }
    }
}
extension Notification.Name { static let enrollmentLink = Notification.Name("io.sbeasy.enrollment") }

struct Dashboard: View {
    @ObservedObject var model: VPNController
    @State private var importSheet = false
    @State private var preferencesSheet = false
    @State private var removeConfirmation = false
    @State private var enrollment = ""
    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(model.statusText).font(.title2.bold())
                            Text(model.selected?.name ?? "添加管理配置或独立订阅").foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(model.active ? "断开" : "连接") { model.active ? model.disconnect() : model.connect() }
                            .disabled(model.busy || model.selected == nil || model.status == .disconnecting)
                    }
                    if model.rollback { Text("更新未通过，当前使用上次成功配置").foregroundStyle(.orange) }
                    if let live = model.live {
                        if live.traffic_available {
                            HStack {
                                Label(ByteCountFormatter.string(fromByteCount: live.upload_total, countStyle: .binary), systemImage: "arrow.up")
                                Spacer()
                                Label(ByteCountFormatter.string(fromByteCount: live.download_total, countStyle: .binary), systemImage: "arrow.down")
                            }
                        }
                        Text("活动连接 \(live.connections) · 内存 \(ByteCountFormatter.string(fromByteCount: live.memory_bytes, countStyle: .memory))")
                            .font(.caption).foregroundStyle(.secondary)
                    } else if model.status == .connected { Text("正在读取实时状态…").foregroundStyle(.secondary) }
                    if model.busy { ProgressView() }
                    if let error = model.error { Text(error).foregroundStyle(.red) }
                }
                Section("配置") {
                    ForEach(model.state.profiles) { profile in
                        Button { model.selectProfile(profile.id) } label: {
                            HStack {
                                Image(systemName: profile.id == model.state.selectedID ? "checkmark.circle.fill" : "circle")
                                Text(profile.name); Spacer(); Text(profile.mode == .managed ? "管理模式" : "独立模式").foregroundStyle(.secondary)
                            }
                        }.disabled(model.active || model.busy)
                    }
                    Button { importSheet = true } label: { Label("添加配置或订阅", systemImage: "plus") }.disabled(model.busy)
                    if model.selected != nil {
                        Button { model.refresh() } label: { Label("刷新配置与订阅", systemImage: "arrow.clockwise") }.disabled(model.busy)
                        Button { preferencesSheet = true } label: { Label("本地默认节点与域名分组", systemImage: "point.3.connected.trianglepath.dotted") }.disabled(model.active || model.busy)
                        Button("删除当前配置", role: .destructive) { removeConfirmation = true }.disabled(model.active || model.busy)
                    }
                }
                if let groups = model.live?.groups {
                    ForEach(groups) { group in
                        Section(group.tag) {
                            ForEach(group.items) { item in
                                Button { model.select(group: group.tag, target: item.tag) } label: {
                                    HStack {
                                        Image(systemName: group.selected == item.tag ? "checkmark.circle.fill" : "circle")
                                        Text(item.tag); Spacer()
                                        if let delay = item.delay_ms, delay > 0 { Text("\(delay) ms").foregroundStyle(.secondary) }
                                    }
                                }.disabled(!group.selectable || model.busy)
                            }
                            Button("测量此组延迟") { model.probe(group.tag) }.disabled(model.busy)
                        }
                    }
                }
                if let profile = model.selected {
                    Section("订阅") {
                        ForEach(profile.subscriptions) { subscription in
                            VStack(alignment: .leading, spacing: 5) {
                                Text(subscription.name).font(.headline)
                                Text("\(subscription.report.imported) 个节点 · 跳过 \(subscription.report.skipped) 项").font(.caption)
                                if let warnings = subscription.report.warnings, !warnings.isEmpty {
                                    DisclosureGroup("未导入条目") { ForEach(Array(warnings.enumerated()), id: \.offset) { entry in Text(entry.element).font(.caption) } }
                                }
                                if let success = subscription.lastSuccess { Text("更新于 \(success.formatted())").font(.caption).foregroundStyle(.secondary) }
                                if let error = subscription.lastError { Text(error).foregroundStyle(.orange) }
                                if subscription.remote {
                                    Picker("自动刷新", selection: Binding(get: { subscription.refreshMinutes }, set: { minutes in
                                        model.run { try await Repository.shared.refreshInterval(profileID: profile.id, subscriptionID: subscription.id, minutes: minutes) }
                                    })) { Text("关闭").tag(0); Text("每小时").tag(60); Text("每六小时").tag(360); Text("每天").tag(1440) }.disabled(model.busy)
                                }
                                if subscription.metadata.available {
                                    if let used = subscription.metadata.used_bytes {
                                        Text("已用 \(ByteCountFormatter.string(fromByteCount: Int64(used), countStyle: .binary))").font(.caption)
                                    }
                                    if let remaining = subscription.metadata.remaining_bytes { Text("剩余 \(ByteCountFormatter.string(fromByteCount: Int64(remaining), countStyle: .binary))").font(.caption) }
                                    if let expires = subscription.metadata.expires_at, expires > 0 {
                                        Text("到期 \(Date(timeIntervalSince1970: expires).formatted(date: .abbreviated, time: .omitted))").font(.caption)
                                        if expires <= Date().timeIntervalSince1970 { Text("订阅已到期").foregroundStyle(.orange) }
                                    }
                                    if subscription.metadata.quota_exhausted == true { Text("订阅流量已耗尽").foregroundStyle(.orange) }
                                } else { Text("服务未提供流量与到期信息").font(.caption).foregroundStyle(.secondary) }
                                Button("移除此订阅", role: .destructive) {
                                    model.run { try await Repository.shared.removeSubscription(profileID: profile.id, subscriptionID: subscription.id) }
                                }.disabled(model.active || model.busy)
                            }
                        }
                    }
                }
            }
            .navigationTitle("sb-easy")
            .sheet(isPresented: $importSheet) { ImportView(model: model, enrollment: enrollment) }
            .sheet(isPresented: $preferencesSheet) { PreferencesView(model: model) }
            .confirmationDialog("删除当前配置和本机凭据？", isPresented: $removeConfirmation) {
                Button("删除配置", role: .destructive) { model.removeProfile() }
            }
            .onReceive(NotificationCenter.default.publisher(for: .enrollmentLink)) { event in
                if let raw = event.object as? String { enrollment = raw; importSheet = true }
            }
        }
    }
}

struct ImportView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: VPNController
    var enrollment: String
    @State private var kind = 0
    @State private var name = ""
    @State private var content = ""
    @State private var addToCurrent = false
    var body: some View {
        NavigationStack {
            Form {
                Picker("导入方式", selection: $kind) {
                    Text("注册链接").tag(0); Text("HTTPS 订阅").tag(1); Text("离线订阅").tag(2)
                }
                TextField("名称", text: $name)
                #if os(tvOS)
                TextField(kind == 0 ? "sbeasy://enroll…" : "订阅地址或内容", text: $content)
                #else
                TextEditor(text: $content).frame(minHeight: 160).font(.body.monospaced())
                #endif
                if kind != 0 && model.selected != nil { Toggle("添加到当前配置", isOn: $addToCurrent) }
                Text(kind == 0 ? "由管理端生成一次性注册链接。" : "支持 URI、Clash YAML 与 sing-box JSON；只导入代理节点。远程订阅每六小时刷新，VPN 运行时由扩展检查。")
                    .foregroundStyle(.secondary)
                Button("导入") {
                    let value = content.trimmingCharacters(in: .whitespacesAndNewlines)
                    model.run {
                        if kind == 0 { try await Repository.shared.enroll(value, name: name) }
                        else if addToCurrent, let id = model.selected?.id {
                            try await Repository.shared.addSubscription(profileID: id, name: name, content: value, remote: kind == 1)
                        } else { try await Repository.shared.createIndependent(name: name, content: value, remote: kind == 1) }
                        dismiss()
                    }
                }.disabled(content.isEmpty || model.busy || (addToCurrent && model.active))
                if model.busy { ProgressView() }
                if let error = model.error { Text(error).foregroundStyle(.red) }
            }.navigationTitle("添加配置").toolbar { Button("关闭") { dismiss() } }
            .onAppear { if !enrollment.isEmpty { content = enrollment; kind = 0 } }
        }
    }
}

struct PreferencesView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: VPNController
    @State private var preferences = Preferences()
    @State private var nodes: [String] = []
    @State private var groupName = ""
    @State private var domains = ""
    @State private var target = ""
    var body: some View {
        NavigationStack {
            Form {
                Picker("默认节点", selection: Binding(get: { preferences.selected_tag ?? "" }, set: { preferences.selected_tag = $0.isEmpty ? nil : $0 })) {
                    Text("跟随策略组").tag("")
                    ForEach(nodes, id: \.self) { Text($0).tag($0) }
                }
                Section("本地域名分组") {
                    ForEach(preferences.local_groups) { group in
                        VStack(alignment: .leading) {
                            Text(group.name); Text(group.domains.joined(separator: ", ")).font(.caption)
                            Text(group.outbound).font(.caption).foregroundStyle(.secondary)
                            Button("删除分组", role: .destructive) { preferences.local_groups.removeAll { $0.id == group.id } }
                        }
                    }
                    TextField("分组名称", text: $groupName)
                    TextField("域名，以逗号分隔", text: $domains)
                    Picker("分组节点", selection: $target) { Text("选择节点").tag(""); ForEach(nodes, id: \.self) { Text($0).tag($0) } }
                    Button("添加分组") {
                        let values = domains.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map { $0.lowercased() }
                        preferences.local_groups.append(LocalGroup(name: groupName, domains: values, outbound: target))
                        groupName = ""; domains = ""
                    }.disabled(groupName.isEmpty || domains.isEmpty || target.isEmpty)
                    Text("域名分组也用于 DNS 出口。管理端的精确地址、私有网络与保护规则保持优先。").font(.caption).foregroundStyle(.secondary)
                }
                Button("保存") {
                    guard let id = model.selected?.id else { return }
                    model.run { try await Repository.shared.preferences(preferences, profileID: id); dismiss() }
                }.disabled(model.busy || model.active)
                if let error = model.error { Text(error).foregroundStyle(.red) }
            }.navigationTitle("本地设置").toolbar { Button("关闭") { dismiss() } }
            .task {
                guard let profile = model.selected else { return }
                preferences = profile.preferences
                if let (_, credentials) = try? await SecureStore.shared.profile(profile.id),
                   let runtime = try? Core.runtime(profile, credentials: credentials) { nodes = (try? Core.outboundTags(runtime)) ?? [] }
            }
        }
    }
}
