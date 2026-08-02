package org.telegram.messenger;

import android.content.Context;
import android.content.Intent;
import android.os.FileObserver;

import java.io.File;
import java.io.FileInputStream;

/**
 * Watches the subscription verdict the native transport writes out.
 *
 * The native layer learns the verdict first - it is the thing holding the
 * connection - but it is C++ with no route into the UI. Rather than add a JNI
 * callback (three new patch anchors in files upstream edits constantly) it
 * drops a small file and this class watches for it.
 *
 * The watch is on the *directory*, not the file: native writes to a temp name
 * and renames it into place so a reader never sees a half-written file, and a
 * FileObserver attached to the file's inode would not see that rename at all.
 */
public class RelayStatus {

    public static final int ST_OK = 0x00;
    public static final int ST_EXPIRED = 0x01;
    public static final int ST_DEVICE_LIMIT = 0x02;
    public static final int ST_SUSPENDED = 0x03;
    public static final int ST_QUOTA = 0x04;

    private static final String FILE = "relay.status";

    private static FileObserver observer;
    private static String dirPath;
    private static volatile boolean haveRead;
    private static volatile int status = ST_OK;
    private static volatile int ttlDays = -1;
    private static volatile long updatedAt;

    public static int getStatus() {
        return haveRead ? status : CustomConfig.getSubStatus();
    }

    public static int getTtlDays() {
        return ttlDays;
    }

    /**
     * True when the relay refused us for a reason the user can act on.
     *
     * Falls back to the last verdict persisted in preferences, because callers
     * may ask before the status file has been read - notably the launch gate,
     * which runs before the network layer is up. Without that fallback an
     * expired subscription would show as "connecting..." forever instead of the
     * renewal screen.
     */
    public static boolean isBlocking() {
        return getStatus() != ST_OK;
    }

    /** true when the subscription is close enough to warrant a nudge */
    public static boolean expiringSoon() {
        return status == ST_OK && ttlDays >= 0 && ttlDays <= 3;
    }

    public static synchronized void start(String configPath) {
        read(new File(configPath, FILE));
        if (observer != null && configPath.equals(dirPath)) {
            return;
        }
        if (observer != null) {
            // called once per account; without this each extra account leaves
            // its predecessor watching a directory nobody writes to any more
            try {
                observer.stopWatching();
            } catch (Throwable ignore) {
            }
            observer = null;
        }
        dirPath = configPath;
        try {
            observer = new FileObserver(configPath,
                    FileObserver.CLOSE_WRITE | FileObserver.MOVED_TO) {
                @Override
                public void onEvent(int event, String path) {
                    if (path == null || !FILE.equals(path)) {
                        return;
                    }
                    int before = status;
                    read(new File(dirPath, FILE));
                    if (status != before && status != ST_OK) {
                        openRenewal();
                    }
                }
            };
            observer.startWatching();
        } catch (Throwable ignore) {
        }
    }

    private static void read(File f) {
        FileInputStream in = null;
        try {
            if (!f.exists()) {
                return;
            }
            in = new FileInputStream(f);
            byte[] buf = new byte[256];
            int n = in.read(buf);
            if (n <= 0) {
                return;
            }
            for (String line : new String(buf, 0, n, "US-ASCII").split("\n")) {
                int eq = line.indexOf('=');
                if (eq <= 0) {
                    continue;
                }
                String k = line.substring(0, eq).trim();
                String v = line.substring(eq + 1).trim();
                try {
                    if ("status".equals(k)) {
                        status = Integer.parseInt(v);
                    } else if ("ttl".equals(k)) {
                        ttlDays = Integer.parseInt(v);
                    } else if ("ts".equals(k)) {
                        updatedAt = Long.parseLong(v);
                    }
                } catch (NumberFormatException ignore) {
                }
            }
            haveRead = true;
            CustomConfig.setSubscription(status, ttlDays);
        } catch (Throwable ignore) {
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (Throwable ignore) {
            }
        }
    }

    /**
     * Best-effort: raise the renewal screen as soon as the verdict lands.
     *
     * Android 10 and later refuse activity starts from the background, so this
     * only works while the app is in the foreground. The reliable path is the
     * launch gate, which checks {@link #isBlocking()} on the next start - this
     * is here so a subscription that lapses mid-session says so immediately
     * instead of turning into a silent "connecting...".
     */
    private static void openRenewal() {
        try {
            Context ctx = ApplicationLoader.applicationContext;
            Intent i = new Intent(ctx, ConfigActivity.class);
            i.putExtra(ConfigActivity.EXTRA_STEP, ConfigActivity.STEP_RENEWAL);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            ctx.startActivity(i);
        } catch (Throwable ignore) {
        }
    }

    /** Human text for the current verdict. */
    public static String describe() {
        switch (status) {
            case ST_EXPIRED:
                return "Your subscription has expired.";
            case ST_DEVICE_LIMIT:
                return "This subscription is in use on too many devices.";
            case ST_SUSPENDED:
                return "This subscription is not active.";
            case ST_QUOTA:
                return "This subscription is over its traffic quota.";
            default:
                return ttlDays >= 0 && ttlDays < 0xFFFF
                        ? "Subscription active, " + ttlDays + " day(s) left."
                        : "Subscription active.";
        }
    }
}
