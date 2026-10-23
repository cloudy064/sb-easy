# Android 应用与内核更新协议 v1

本协议用于 F11 的 Android 主应用更新；Windows 更新使用自己的签名清单。Android 内核随主应用 APK 一起发布，不下载并加载独立可执行内核。应用更新目录与插件目录使用不同格式、公钥配置和签名域。

## 信任与目录

`config/app-catalog-keys.json` 默认是空公钥表，在线更新关闭。发布构建通过 Gradle `-PsbAppCatalogKeys=/absolute/public-keys.json` 注入审核后的公钥。目录内不能引入公钥。应用与 HTTP 插件的 APK 签名统一使用 `android/signing.gradle` 的外部 keystore 参数；签名私钥、密码与目录私钥均不存入仓库。

公钥格式为 `{"format":"sb-easy.app-catalog.keys","version":1,"keys":{"publisher-id":"BASE64_SPKI_DER"}}`，最多 16 个 RSA 2048–4096 位公钥。目录 envelope 的字段严格为 `format`、`version`、`algorithm`、`key_id`、`payload`、`signature`；其值分别使用 `sb-easy.app-catalog`、`1`、`rsa-pss-sha256`、受信任密钥 ID，以及规范 Base64 编码的 payload 原始 UTF-8 字节和签名。

签名输入为 ASCII `sb-easy.app-catalog/v1\n`（末尾一个 LF 字节）加上原样 payload。算法为 RSA-PSS、SHA-256、MGF1-SHA256、salt 长度 32、trailer=1。插件目录的签名不能重包装成应用目录。payload 不做 JSON 重排或规范化；所有对象拒绝重复、未知或缺失字段，拒绝错误 UTF-8、非整数版本字段和额外尾随内容。envelope 上限 1 MiB、payload 上限 512 KiB。

payload 字段：

| 字段 | 约束 |
| --- | --- |
| `sequence` | 1 到 2^53−1 的整数；持久化后只增不减，同序号只接受相同 payload 摘要 |
| `issued_at` / `expires_at` | Unix 秒整数；有效期 1 秒至 90 天，签发时间最多领先本机 300 秒，新下载必须未过期 |
| `releases` | 最多 128 个版本记录 |
| `revocations` | 最多 256 个 `{build,reason}`；本机跨目录累计撤销且不随旧目录消失 |

版本记录字段严格为：

| 字段 | 约束 |
| --- | --- |
| `version` / `build` | 三段数字版本名；versionCode 为 1–2100000000 |
| `package` | 固定为 `io.sbeasy.android` |
| `min_os` | 24–999；必须与 APK 真实 minSdkVersion 一致 |
| `abis` | 无重复的 `arm64-v8a`、`armeabi-v7a`、`x86`、`x86_64` 子集；必须与 APK 原生库架构集合完全一致且支持本机 |
| `signer_sha256` | 单一当前 APK 签名证书的 SHA-256；同时必须等于当前已安装应用的单一证书，不自动信任轮换谱系 |
| `url` | HTTPS，无账户信息或片段；不跟随重定向 |
| `sha256` / `bytes` | APK 精确 SHA-256 与字节数，上限 160 MiB |
| `core_version` / `source_revision` | 内核三段版本与完整 40 位小写 Git revision |
| `provenance_sha256` | APK 的 `assets/libbox-provenance.json` 原始字节 SHA-256 |

相同 build 与 ABI 集合不重复。相同 build 的不同 ABI 包必须共享版本名、签名证书、系统要求、core version、source revision 和 provenance 摘要。撤销按 build 覆盖其所有 ABI 包。

## 实际构建来源

`android/scripts/build-libbox.sh` 验证 `config/runtime-versions.json` 固定的源码 revision，应用 capture overlay 并从校验过的 libpcap 归档构建。它在构建前记录源码差异、额外源文件、overlay/构建脚本/libpcap 摘要和工具链版本；构建后再次确认输入没有变化，才生成 `libbox-provenance.json` sidecar。

sidecar 绑定实际 AAR SHA-256 和四个 ABI 的 `libbox.so` SHA-256，并声明 `source_kind=local-pinned-build`。Gradle 打包前要求 sidecar 与真实 AAR、当前 runtime manifest、overlay 和工具链固定版本一致，再复制到 APK assets；缺失或不匹配时拒绝构建。相同版本号的外部 AAR 不能复用另一份构建的来源声明。APK 保留 `libbox.so` 字节，避免后续 strip 使原生库与来源摘要分离。

安装校验先检查实际 APK 大小与摘要，再读取 Android PackageManager 提供的包名、版本、min SDK、当前证书、shared UID 与调试标志，最后逐架构流式验证 APK 内 `libbox.so` 与被目录签名绑定的 provenance。正式宿主不能安装调试 APK，不接受 shared UID。来源记录证明发布物与记录的本地构建输入和产物绑定；它不是独立的可重现构建证明，目录发布者仍需审核构建环境。

## 更新、失败与恢复

界面提供 HTTPS 目录及本地签名目录导入；不接受绕过目录的本地 APK 更新。在线下载只允许更高 versionCode。在下载前，当前安装包必须匹配当前目录或既有已验证缓存中的签名记录，并保存为恢复副本。已被撤销的当前版本可升级到安全版本，但不能保留为恢复候选。分拆 APK 安装无法作为单一 APK 备份，会明确拒绝该更新路径。

网络请求与下载均有连接、读取和总时限；超出声明长度、提前中断、HTTP 重定向、TLS 失败或摘要不符会丢弃 `.part`，保留现有安装及已验证缓存。完整校验后以原子文件写入目录回执并重命名提交 APK，保留当前与目标两份缓存。缓存使用前重新核验目录签名、APK、兼容性与当前累计撤销；缓存恢复允许原签名回执过期，不能忽略已知撤销。

安装通过 Android `PackageInstaller.Session`，API 31+ 显式要求 `USER_ACTION_REQUIRED`，使用显式、未导出的结果 Activity 和有随机 nonce 的 mutable PendingIntent 接收系统确认/结果。系统安装回调 API 的要求见 [Android Session 文档](https://developer.android.com/reference/android/content/pm/PackageInstaller.Session) 和 [SessionParams 文档](https://developer.android.com/reference/android/content/pm/PackageInstaller.SessionParams)。开始安装及系统确认前均要求 VPN 已断开；不会静默安装或自动恢复 VPN。

提交任何系统安装会话前，必须通过系统文档选择器把**应用外救援 ZIP**保存到可读写的位置。ZIP 同时包含经过重新验证的恢复 APK、完整签名回执、使用用户口令加密的 `preferences.sbp` 和无需启动应用即可阅读的中英文 `RECOVERY.txt`。写完后重新打开文件校验整个 ZIP 的 SHA-256；安装层还会核对当前 APK、目标 APK、偏好快照与这份读回记录，不允许只靠界面按钮绕过。文件不可读、内容被替换、偏好变更或恢复版本被撤销时要求重新导出。应用专属外部目录与宿主 FileProvider 不能作为救援目的地。

正常情况下恢复 APK 是当前已安装版本。若当前版本已撤销，优先选择已验证且未撤销的旧缓存；没有安全旧版时只保存本次目标 APK 和偏好，并明确显示“不能回退旧版”。不允许为了可回退而重新导出已知撤销的代码。即使新版本安装成功后启动即崩溃，用户仍可用系统文件管理器解压已保存的救援 ZIP，再按说明手动卸载重装；应用私有缓存不再是唯一救援材料。

Android 不允许普通应用直接降低 versionCode。较旧缓存的恢复方式是：

1. 导出经过重新验证的恢复 ZIP，内含旧 APK、完整签名目录和恢复说明。
2. 另行导出加密偏好，确认两份文件位于应用私有存储之外且能够读取。
3. 由用户手动卸载当前应用，再从恢复 ZIP 提取 APK 并经系统确认安装，导入加密偏好；受管设备重新注册。

卸载会清除本机令牌、WireGuard 私钥、CA 私有材料、更新缓存以及目录序号/撤销状态。可迁移偏好刻意不包含这些内容。重装后应读取最新签名目录恢复撤销状态；离线设备只知道此前取得的撤销信息。本功能不声称原子、静默或无损降级，也不能在卸载之后保留防重放基线。

## 发布工具

外部发布者公钥先转成构建信任配置：

```bash
python3 updates/android/publish.py trust --public-key /secure/publisher-public.pem \
  --key-id publisher-2026 --output /secure/app-public-keys.json
# 构建 app 时：-PsbAppCatalogKeys=/secure/app-public-keys.json
```

从实际 APK 生成版本记录（会调用 aapt2/apksigner 并核验 provenance/原生库），将当前版与目标版记录放入 payload 的 `releases` 数组：

```bash
python3 updates/android/publish.py release --apk build/releases/sb-easy.apk \
  --url https://downloads.example.org/sb-easy.apk \
  --build-tools "$ANDROID_HOME/build-tools/36.0.0" --output build/release.json
python3 updates/android/publish.py sign --payload /secure/app-payload.json \
  --private-key /secure/publisher-private.pem --key-id publisher-2026 \
  --keys /secure/app-public-keys.json --artifact-root build/releases \
  --build-tools "$ANDROID_HOME/build-tools/36.0.0" --output build/app-catalog.json
python3 updates/android/publish.py verify --catalog build/app-catalog.json --keys /secure/app-public-keys.json
```

`sign` 必须提供实际发布 APK 所在目录，并重新核验每份实际 APK 与 payload 的所有字段；目录私钥必须对应已注入宿主的公钥。仓库不提供生产私钥、发布域名或虚构的正式更新源。

## 验证边界

JVM 测试覆盖 OpenSSL/PSS 互操作与域分离、严格 JSON、序号/过期、单证书/manifest/ABI 策略、内核来源篡改、真实 HTTPS 测试服务器上的重定向、TLS、大小、摘要与残留文件。Android instrumentation 测试核验实际安装包及内核来源，需设备执行；没有在线设备时只构建该测试 APK，不声称真机安装、系统确认、自更新重启或卸载恢复验收通过。

应用外救援测试实际生成 ZIP，核对 APK/签名回执的原始字节、解密偏好往返，以及截断、篡改、源 APK 变化、明文偏好和文档写入错误的拒绝。真实 SAF 提供者、系统安装回调和卸载恢复仍属于设备验收。
