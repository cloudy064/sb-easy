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
    @Override public void onCreate() {
        super.onCreate();
        worker = new HandlerThread("http-debug-control"); worker.start();
        messenger = new Messenger(new Handler(worker.getLooper(), msg -> {
            Bundle reply = new Bundle();
            try {
                if (!Python.isStarted()) Python.start(new AndroidPlatform(this));
                String method = msg.getData().getString("method", "snapshot");
                if (!java.util.Arrays.asList("start", "snapshot", "stop", "certificate").contains(method))
                    throw new IllegalArgumentException("Unknown operation");
                JSONObject params = new JSONObject();
                if (method.equals("start")) params.put("directory", new java.io.File(getFilesDir(), "ca").getAbsolutePath());
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
        worker.quitSafely(); super.onDestroy(); android.os.Process.killProcess(android.os.Process.myPid());
    }
}
