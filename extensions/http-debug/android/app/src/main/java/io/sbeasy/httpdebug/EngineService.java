package io.sbeasy.httpdebug;

import android.app.Service;
import android.content.Intent;
import android.os.*;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;
import org.json.JSONObject;

/** Bound to the foreground VPN host. No second VPN, remote server or public API. */
public final class EngineService extends Service {
    private HandlerThread worker;
    private Messenger messenger;
    private java.io.File authorityDirectory() { return new java.io.File(getFilesDir(), "ca"); }
    private void removeAuthority(java.io.File file) {
        java.io.File[] children = file.listFiles();
        if (children != null) for (java.io.File child : children) removeAuthority(child);
        if (file.exists() && !file.delete()) throw new IllegalStateException("Unable to remove old debug authority");
    }
    @Override public void onCreate() {
        super.onCreate();
        // Also remove keys orphaned by a previous crash or process kill.
        removeAuthority(authorityDirectory());
        worker = new HandlerThread("http-debug-control"); worker.start();
        messenger = new Messenger(new Handler(worker.getLooper(), msg -> {
            Bundle reply = new Bundle();
            try {
                int hostUid = getPackageManager().getApplicationInfo("io.sbeasy.android", 0).uid;
                if (msg.sendingUid != hostUid || getPackageManager().checkSignatures(msg.sendingUid, getApplicationInfo().uid)
                        != android.content.pm.PackageManager.SIGNATURE_MATCH)
                    throw new SecurityException("Caller is not the signed sb-easy host");
                if (!Python.isStarted()) Python.start(new AndroidPlatform(this));
                String method = msg.getData().getString("method", "snapshot");
                if (!java.util.Arrays.asList("start", "snapshot", "stop", "certificate", "clear").contains(method))
                    throw new IllegalArgumentException("Unknown operation");
                JSONObject params = new JSONObject();
                if (method.equals("start") || method.equals("clear") || method.equals("stop")) params.put("directory", authorityDirectory().getAbsolutePath());
                String result = Python.getInstance().getModule("engine").callAttr("android_call", method, params.toString()).toString();
                reply.putString("result", result);
            } catch (Exception error) { reply.putString("error", error.getMessage()); }
            Message response = Message.obtain(null, msg.what); response.setData(reply);
            try { if (msg.replyTo != null) msg.replyTo.send(response); } catch (RemoteException ignored) { }
            return true;
        }));
    }
    @Override public IBinder onBind(Intent intent) { return messenger.getBinder(); }
    @Override public void onDestroy() {
        // The plugin has its own process. Killing it closes all interception
        // sockets even if Python is still starting or a TLS handshake hangs.
        worker.quitSafely();
        try { removeAuthority(authorityDirectory()); } catch (RuntimeException ignored) { /* Retried before next start. */ }
        super.onDestroy(); android.os.Process.killProcess(android.os.Process.myPid());
    }
}
