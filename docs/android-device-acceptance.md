# Android 隔离验收

当前环境完成 JVM/原生 Linux 核心检查、APK 构建和下述 **host fixture 自检**，没有在线 Android 设备。下述 instrumentation 入口已编译，设备验收状态为 **NOT RUN**。不把 host 自检的合成 PCAP 当作真实 Android TUN 抓包证据。

## 无设备运行 fixture 自检

在仓库根目录使用已构建的 C 中心：

```sh
python3 scripts/android-device-acceptance.py --self-check \
  --server build/c-proxy-users/sb-easy-c-server
```

脚本创建临时数据库、管理员、仅本次使用的 Android profile 和设备注册，不接触已有部署。HTTP/UDP echo、注册/配置 API、采集上传/下载、重复上传和认证/坏文件拒绝都通过真实 C 服务执行。输出目录保存报告和脱敏日志；数据库与原始 PCAP 默认删除，`--keep-private-data` 才保留。自检报告始终把 native 验收列为未运行。

## 准备测试包与设备

只使用无生产数据的测试设备。先手动授予 sb-easy VPN 权限，再停止 VPN。选择与设备 ABI 匹配的主 APK；HTTP 调试插件只提供 ARM64/x86_64。主应用、插件和辅助 probe 必须用同一外部 keystore，参数见 [插件目录协议](plugin-catalog-v1.md)。普通 Android 升级仍要求已安装版本具有相同签名；脚本不卸载现有应用。

```sh
bash android/gradlew -p android :app:assembleDebug :app:assembleDebugAndroidTest
extensions/http-debug/build-android.sh
bash android/gradlew -p extensions/http-debug/android :probe:assembleDebug
```

probe 是测试专用 APK `io.sbeasy.sandboxprobe`，不属于插件发行包，不要安装到生产设备。三个 APK 的签名可分别用 Android SDK `apksigner verify --print-certs <apk>` 比较。

## 原始采集与插件隔离

下面以 ARM64、同一局域网中的测试主机 `192.168.1.20` 为例。`SERIAL` 必须明确填写；脚本不会自动选设备。只在明确传入 `--*-apk` 时执行 `adb install -r`，省略这些参数会检查既有安装。

```sh
python3 scripts/android-device-acceptance.py \
  --device SERIAL --isolated-device --device-host 192.168.1.20 \
  --server build/c-proxy-users/sb-easy-c-server --tests all \
  --app-apk android/app/build/outputs/apk/debug/app-arm64-v8a-debug.apk \
  --test-apk android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk \
  --plugin-apk build/httpdebug-android/http-debug-1.0.1-arm64-v8a.apk \
  --sandbox-probe-apk extensions/http-debug/android/probe/build/outputs/apk/debug/probe-debug.apk
```

模拟器可显式使用 `--device-host 10.0.2.2 --bind-address 127.0.0.1`。网络必须允许设备访问本次 fixture 的临时端口。脚本不使用 adb reverse，也不修改防火墙、系统 CA、VPN 授权或清除应用数据。结束和超时会停止这次选定的测试应用。

| `--tests` | 设备证据 |
| --- | --- |
| `capture` | 只把 fixture IPv4 `/32`、主应用包名送入 TUN；域名后缀/精确 host、应用归属、双向 TCP/UDP、BPF 组合/排除、PCAP 封存与上传；中心独立检查上传摘要和正负流量标记。前台服务入口兼容 API 24/25。 |
| `http-debug` | VPN 停止时实际启动插件，通过带鉴权的回程代理截获 `www.example.com` HTTPS、读取响应/HAR、停止与 CA 清理/重新生成。需要外网。 |
| `sandbox` | 同签名的 probe 拥有 signature permission，但处于第三个 UID；实际读取主应用私有 canary 被拒，向插件发送控制消息也被实际 host UID 检查拒绝。 |
| `all` | 上述三项；不包含下面的全 IPv4 VPN 用例。 |

缺少设备、包或 VPN 授权、instrumentation 被跳过或没有执行测试时，不报告通过。结果文件与仪器输出只说明实际已执行的项目。

## 明确选择真实 VPN HTTP 调试

```sh
python3 scripts/android-device-acceptance.py \
  --device SERIAL --isolated-device --device-host 192.168.1.20 \
  --server build/c-proxy-users/sb-easy-c-server --tests http-debug-vpn
```

这一独立模式创建 `0.0.0.0/0` 的 IPv4 TUN profile，但仍只包含主应用包名；不会修改前面的 `/32` 采集 profile。设备需要匹配的插件与外网。测试使用真正的 `HttpDebug.start/attach`：普通 TLS 成功 → 指定域名由 TUN 进入插件 → HAR 出现本次随机标记 → 停止后普通 TLS 恢复、三个 loopback 监听端口关闭 → 本地 CA 重新生成、Android 信任存储不存在追踪的 CA。

HTTPS 测试只把调试 CA 放进测试进程的临时 TrustManager，**不安装系统 CA**。系统用户 CA 安装、其他应用是否信任该 CA、系统设置删除 CA，以及不同 ROM 的行为仍需人工验收；证书固定不在测试能力内。

## 应用更新与系统阻断的人工验收

`AppUpdatePackageTest` 可用 AndroidJUnitRunner 检查设备上真实安装 APK 的 manifest、签名和逐 ABI 内核来源，不能替代系统安装确认。应用更新验收需在隔离设备配置测试签名目录，验证取消/失败、更新后启动、撤销拒绝，以及安装前强制导出的外部救援 ZIP。验证 ZIP 可读后模拟新版无法启动，从系统文件管理器解压；手动卸载、安装已验证旧 APK、输入口令导入偏好并重新注册。卸载会丢失设备秘密与本地信任状态，不能声称无损回滚。完整格式见 [应用更新协议](android-app-updates-v1.md)。

“设置 → 系统 VPN”提供系统入口，并在服务运行且 API ≥29 时读取实际 Always-on/lockdown 状态。需由测试人员在系统设置启用两项，再验证断开、进程退出、切网及 DNS/IPv6/UDP 流量阻断；脚本不替用户修改这些开关。
