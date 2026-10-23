package io.sbeasy.sandboxprobe;

import android.app.Service;
import android.content.*;
import android.content.pm.PackageManager;
import android.os.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/** Opt-in test adversary: same certificate and granted IPC permission, different UID. */
public final class ProbeService extends Service {
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Messenger messenger = new Messenger(new Handler(Looper.getMainLooper(), message -> {
        Bundle result = new Bundle();
        final Messenger recipient = message.replyTo;
        try {
            int hostUid = getPackageManager().getApplicationInfo("io.sbeasy.android", 0).uid;
            if (message.sendingUid != hostUid || getPackageManager().checkSignatures(hostUid, getApplicationInfo().uid) != PackageManager.SIGNATURE_MATCH)
                throw new SecurityException("Only the signed test host may invoke the probe");
            result.putInt("probeUid", android.os.Process.myUid());
            result.putInt("hostUid", hostUid);
            result.putInt("pluginUid", getPackageManager().getApplicationInfo("io.sbeasy.httpdebug", 0).uid);
            result.putBoolean("signaturePermissionGranted", checkSelfPermission("io.sbeasy.android.permission.HTTP_DEBUG") == PackageManager.PERMISSION_GRANTED);
            File canary = new File(message.getData().getString("canary", ""));
            File hostFiles = new File(getPackageManager().getApplicationInfo("io.sbeasy.android", 0).dataDir, "files");
            if (!hostFiles.getAbsoluteFile().equals(canary.getAbsoluteFile().getParentFile()) || !canary.getName().matches("sandbox-probe-[0-9a-f]+"))
                throw new IllegalArgumentException("Only the host test canary is allowed");
            try (FileInputStream input = new FileInputStream(canary)) {
                input.read(); result.putBoolean("privateFileDenied", false);
            } catch (IOException denied) { result.putBoolean("privateFileDenied", true); }
            new Attempt(recipient, result).start();
        } catch (Exception error) {
            result.putString("error", error.toString()); send(recipient, result);
        }
        return true;
    }));

    private void send(Messenger recipient, Bundle result) {
        try {
            if (recipient != null) {
                Message message = Message.obtain(null, 1); message.setData(result); recipient.send(message);
            }
        }
        catch (RemoteException ignored) { }
    }

    private final class Attempt implements ServiceConnection {
        final Messenger recipient;
        final Bundle result;
        boolean bound, finished;
        final Runnable timeout;
        Attempt(Messenger recipient, Bundle result) {
            this.recipient = recipient; this.result = result;
            timeout = () -> { this.result.putString("error", "Plugin IPC probe timed out"); finish(); };
        }
        void start() {
            try {
                bound = bindService(new Intent().setComponent(new ComponentName("io.sbeasy.httpdebug", "io.sbeasy.httpdebug.EngineService")), this, BIND_AUTO_CREATE);
                if (!bound) throw new IllegalStateException("Plugin binding returned false");
                main.postDelayed(timeout, 15000);
            } catch (RuntimeException error) { result.putString("error", error.toString()); finish(); }
        }
        void finish() {
            if (finished) return;
            finished = true; main.removeCallbacks(timeout);
            if (bound) { unbindService(this); bound = false; }
            send(recipient, result);
        }
        @Override public void onServiceConnected(ComponentName name, IBinder binder) {
            Messenger response = new Messenger(new Handler(Looper.getMainLooper(), reply -> {
                String error = reply.getData().getString("error", "");
                result.putString("pluginError", error);
                result.putBoolean("hostUidGateRejected", error.equals("Caller is not the signed sb-easy host"));
                finish(); return true;
            }));
            Message request = Message.obtain(null, 1);
            request.replyTo = response;
            Bundle data = new Bundle(); data.putString("method", "snapshot"); request.setData(data);
            try { new Messenger(binder).send(request); }
            catch (RemoteException error) { result.putString("error", error.toString()); finish(); }
        }
        @Override public void onServiceDisconnected(ComponentName name) { result.putString("error", "Plugin disconnected before reply"); finish(); }
        @Override public void onNullBinding(ComponentName name) { result.putString("error", "Plugin returned a null binding"); finish(); }
    }

    @Override public IBinder onBind(Intent intent) { return messenger.getBinder(); }
}
