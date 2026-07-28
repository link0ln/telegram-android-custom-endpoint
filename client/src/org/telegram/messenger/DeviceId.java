package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.security.SecureRandom;

/**
 * A stable per-install identifier, used only to count how many devices share a
 * subscription.
 *
 * It is 16 random bytes we generate ourselves, not a hardware identifier.
 * ANDROID_ID, IMEI, serial numbers, MAC addresses and the advertising ID were
 * all rejected: they are permission-gated or policy-restricted, they identify
 * the person rather than the install, and for a censorship-circumvention tool
 * shipping a hardware identifier to a server is exactly the wrong default.
 *
 * Rendered as 32 hex characters, because the native layer has to decode it
 * with no base64 implementation to hand.
 *
 * Reinstalling or clearing app data produces a new id, which counts as a new
 * device. That is intended: it is the same thing the customer experiences as
 * "I wiped my phone", and the vendor can free the old slot from the CLI.
 */
public class DeviceId {

    private static final String KEY = "device_id";
    private static final String MIRROR = ".relaydev";
    private static volatile String cached;

    public static synchronized String get() {
        if (cached != null) {
            return cached;
        }
        SharedPreferences prefs = ApplicationLoader.applicationContext
                .getSharedPreferences("relaycfg", Context.MODE_PRIVATE);
        String id = prefs.getString(KEY, "");
        if (!isValid(id)) {
            id = readMirror();          // survives prefs being lost on its own
        }
        if (!isValid(id)) {
            id = generate();
        }
        prefs.edit().putString(KEY, id).apply();
        writeMirror(id);
        cached = id;
        return id;
    }

    private static boolean isValid(String id) {
        if (id == null || id.length() != 32) {
            return false;
        }
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    private static String generate() {
        byte[] b = new byte[16];
        new SecureRandom().nextBytes(b);
        StringBuilder sb = new StringBuilder(32);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    private static File mirrorFile() {
        return new File(ApplicationLoader.applicationContext.getFilesDir(), MIRROR);
    }

    private static String readMirror() {
        RandomAccessFile f = null;
        try {
            File file = mirrorFile();
            if (!file.exists()) {
                return null;
            }
            f = new RandomAccessFile(file, "r");
            byte[] buf = new byte[32];
            int n = f.read(buf);
            return n == 32 ? new String(buf, 0, 32, "US-ASCII") : null;
        } catch (Throwable ignore) {
            return null;
        } finally {
            try {
                if (f != null) {
                    f.close();
                }
            } catch (Throwable ignore) {
            }
        }
    }

    private static void writeMirror(String id) {
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(mirrorFile(), false);
            out.write(id.getBytes("US-ASCII"));
        } catch (Throwable ignore) {
        } finally {
            try {
                if (out != null) {
                    out.close();
                }
            } catch (Throwable ignore) {
            }
        }
    }

    /** Short form for support ("which of my devices is this?"). */
    public static String shortForm() {
        String id = get();
        return id.length() >= 8 ? id.substring(0, 8) : id;
    }
}
