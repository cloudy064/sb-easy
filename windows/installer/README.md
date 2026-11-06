# Windows installer

The consumer download is `sb-easy-windows-x64.zip`. Extract the entire archive,
then run `sb-easy-windows-setup-x64.exe`. This executable is a launcher: keep
`sb-easy-windows-bootstrapper.exe` beside it in the same folder. Downloading only
the launcher, or running it directly from a ZIP viewer, leaves its installer
payload unavailable.

The archive also includes `sb-easy-windows-x64.msi` for managed deployment where
WebView2 is already available, release metadata, installation instructions,
licenses, and the corresponding sing-box and WiX source archives. Unsigned
builds include the development marker inside the archive. The external
`SHA256SUMS` covers the completed ZIP and the individual release files.
`scripts/build-windows-installer.ps1` produces these assets using the pinned
WiX Toolset 5.0.2 SDK and extensions.

The MSI is per-machine and installs under `%ProgramFiles%\sb-easy`. It owns:

- the `sb-easy` LocalSystem service and checked SCM configuration action;
- the desktop application, local Vue assets, and the Service-embedded pinned
  sing-box/Wintun runtime resources;
- the `sbeasy://` machine protocol handler and Start Menu shortcut;
- an optional current-user Startup shortcut (`INSTALL_STARTUP_SHORTCUT=1`);
- third-party notices and license texts.

The Burn UI exposes the startup option during installation. In maintenance
mode, it exposes `REMOVE_USER_DATA`; data under `%ProgramData%\sb-easy` is
preserved unless the user explicitly checks that option before uninstalling.
The MSI remembers the full data path in HKLM so recursive removal can be
scheduled before MSI costing without deriving a privileged path from user
input.

WebView2 is detected at Microsoft's documented HKLM and HKCU Evergreen client
keys. Its signed bootstrapper is permanent in the chain, so uninstalling
sb-easy never removes a shared Runtime.

The installer build performs non-installing validation on the build machine. It
inspects both manifests and executes a quiet Burn layout through the shipped
launcher to check that WixStdBA can initialize, detect, plan, apply the layout,
and exit cleanly. The launcher smoke test has a 60-second timeout and terminates
only the process tree it started if setup stalls. Launcher regression
tests cover environment-block handling and command-line forwarding; actual
installation and service recovery are checked by the VM lifecycle test.
The build-machine checks never run the package installation sequence. Use the
lifecycle test script only in a disposable Windows VM. Unsigned builds contain
`DEVELOPMENT-UNSIGNED.txt`; they
must not be published as production releases.

The disposable-VM lifecycle test also force-terminates the installed Service and
requires the configured SCM recovery action to return it to `Running` with a new
process before repair and uninstall proceed.

`scripts/test-windows-installer-payload.ps1` additionally creates a Windows
Installer administrative image under `build/`. This executes no product install
sequence but verifies that the native binaries, UI, runtime metadata, and license
files can all be extracted from the MSI CAB. The Windows CI workflow runs both
forms of non-invasive validation.
