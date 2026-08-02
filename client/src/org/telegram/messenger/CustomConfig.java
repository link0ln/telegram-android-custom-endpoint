package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.io.FileWriter;
import java.net.InetAddress;

/**
 * Runtime configuration entered by the user at setup: their own api_id and
 * api_hash, the relay endpoint, and the subscription token. Nothing is baked
 * into the binary.
 *
 * The native layer cannot read SharedPreferences, so everything it needs is
 * mirrored into &lt;configPath&gt;/relay.cfg, which it parses once during init().
 * Because that read happens exactly once, any change here requires restarting
 * the process - which is why ConfigActivity kills itself after saving.
 */
public class CustomConfig {

    /** relay.cfg format version; bumped if the native parser ever changes shape */
    public static final int CFG_VERSION = 2;

    private static SharedPreferences prefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences("relaycfg", Context.MODE_PRIVATE);
    }

    public static int getApiId() {
        return prefs().getInt("api_id", 0);
    }

    public static String getApiHash() {
        return prefs().getString("api_hash", "");
    }

    /** endpoint hostname the user typed (also used as TLS SNI) */
    public static String getEndpoint() {
        return prefs().getString("endpoint", "");
    }

    /** resolved IPv4 of the endpoint (the socket connects here; SNI stays the hostname) */
    public static String getEndpointIp() {
        return prefs().getString("endpoint_ip", "");
    }

    /** relay port; 443 unless a setup code pinned something else (staging) */
    public static int getEndpointPort() {
        int p = prefs().getInt("endpoint_port", 443);
        return p > 0 && p <= 65535 ? p : 443;
    }

    /** subscription token, base32 as printed by the vendor's CLI */
    public static String getToken() {
        return prefs().getString("token", "");
    }

    /**
     * SHA-256 of the relay certificate's public key, as 64 hex characters.
     *
     * The native TLS client does not verify the relay certificate chain, which
     * was harmless while the connection carried only end-to-end encrypted
     * MTProto. It stops being harmless the moment a bearer token travels in
     * that channel: without a pin, an on-path attacker - exactly the adversary
     * this product exists to defeat - can impersonate the relay, collect
     * tokens and fake "your subscription expired". The pin is learned once by
     * RelayClient, which does verify properly, and enforced natively from then
     * on. Empty means unpinned (self-hosting).
     */
    public static String getEndpointPin() {
        return prefs().getString("endpoint_pin", "");
    }

    /** epoch seconds when the subscription lapses; 0 = unknown/never */
    public static long getSubExpiresAt() {
        return prefs().getLong("sub_expires_at", 0L);
    }

    /** last status code seen from the relay (0 = ok); see wire.py ST_* */
    public static int getSubStatus() {
        return prefs().getInt("sub_status", 0);
    }

    public static void setSubscription(int status, int ttlDays) {
        long expires = ttlDays > 0 && ttlDays < 0xFFFF
                ? System.currentTimeMillis() / 1000L + (long) ttlDays * 86400L
                : 0L;
        prefs().edit()
                .putInt("sub_status", status)
                .putLong("sub_expires_at", expires)
                .apply();
    }

    public static boolean isConfigured() {
        return getApiId() != 0
                && !getApiHash().isEmpty()
                && !getEndpoint().isEmpty()
                && !getEndpointIp().isEmpty();
    }

    /** true once the relay endpoint is usable, even if api credentials are not set yet */
    public static boolean hasEndpoint() {
        return !getEndpoint().isEmpty() && !getEndpointIp().isEmpty();
    }

    public static void saveEndpoint(String endpoint, String endpointIp, int port,
                                    String token, String pin) {
        prefs().edit()
                .putString("endpoint", trim(endpoint))
                .putString("endpoint_ip", trim(endpointIp))
                .putInt("endpoint_port", port > 0 && port <= 65535 ? port : 443)
                .putString("token", trim(token))
                .putString("endpoint_pin", trim(pin))
                .commit();   // synchronous: the process may be restarted right after
    }

    public static void saveApiCredentials(int apiId, String apiHash) {
        prefs().edit()
                .putInt("api_id", apiId)
                .putString("api_hash", trim(apiHash))
                .commit();
    }

    public static void save(int apiId, String apiHash, String endpoint, String endpointIp) {
        prefs().edit()
                .putInt("api_id", apiId)
                .putString("api_hash", trim(apiHash))
                .putString("endpoint", trim(endpoint))
                .putString("endpoint_ip", trim(endpointIp))
                .commit();
    }

    /** Wipe everything and go back to behaving like stock Telegram. */
    public static void clear() {
        prefs().edit().clear().commit();
    }

    private static String trim(String s) {
        return s == null ? "" : s.trim();
    }

    /** Resolve a hostname to its first IPv4 address. Call OFF the main thread. Returns null on failure. */
    public static String resolve(String host) {
        try {
            for (InetAddress a : InetAddress.getAllByName(host)) {
                byte[] b = a.getAddress();
                if (b != null && b.length == 4) {
                    return a.getHostAddress();
                }
            }
        } catch (Throwable ignore) {
        }
        return null;
    }

    /**
     * Mirror the config into &lt;configPath&gt;/relay.cfg for native init().
     *
     * Format is key=value, one per line. The previous format was positional,
     * which is fragile in the way that matters here: the native side reads it
     * with fixed-size fgets buffers, so one overlong line silently spills into
     * the next read and shifts every field after it. With keys, an overlong
     * tail just becomes an unknown key and is ignored.
     *
     * Values are sanitised rather than escaped - anything containing a newline
     * or '=' is treated as unset, since no legitimate value contains them.
     */
    public static void writeRelayFile(String configPath) {
        try {
            File f = new File(configPath, "relay.cfg");
            String ip = clean(getEndpointIp());
            String sni = clean(getEndpoint());
            String token = clean(getToken());
            if (ip.isEmpty() || sni.isEmpty()) {
                // no endpoint -> no file -> the native layer behaves like stock Telegram
                if (f.exists()) {
                    f.delete();
                }
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("v=").append(CFG_VERSION).append('\n');
            sb.append("ip=").append(ip).append('\n');
            sb.append("sni=").append(sni).append('\n');
            sb.append("port=").append(getEndpointPort()).append('\n');
            if (!token.isEmpty()) {
                sb.append("token=").append(token).append('\n');
                sb.append("dev=").append(clean(DeviceId.get())).append('\n');
            }
            String pin = clean(getEndpointPin());
            if (!pin.isEmpty()) {
                sb.append("pin=").append(pin).append('\n');
            }
            // One status file for the whole app, not one per account. The
            // native side keeps this path in a process-global, so with several
            // accounts whichever initialises last would win and the verdict
            // would land in an unpredictable account directory - which also
            // makes the documented debug path wrong. The subscription belongs
            // to the install, not to a Telegram account.
            sb.append("status=").append(statusFile().getAbsolutePath()).append('\n');

            FileWriter w = new FileWriter(f, false);
            w.write(sb.toString());
            w.close();
        } catch (Throwable ignore) {
        }
    }

    /**
     * Re-resolve the endpoint and store the result. Call OFF the main thread.
     *
     * The address is otherwise frozen at setup time, so a relay that changes IP
     * would strand every install until its owner re-ran setup by hand. Returns
     * true when the address changed; native only reads relay.cfg during init(),
     * so the new address takes effect on the next process start.
     */
    public static boolean refreshEndpointIp() {
        String host = getEndpoint();
        if (host.isEmpty()) {
            return false;
        }
        String fresh = resolve(host);
        if (fresh == null || fresh.isEmpty() || fresh.equals(getEndpointIp())) {
            return false;
        }
        prefs().edit().putString("endpoint_ip", fresh).commit();
        return true;
    }

    /** Where the native layer drops the subscription verdict; app-wide. */
    public static File statusFile() {
        return new File(ApplicationLoader.applicationContext.getFilesDir(), "relay.status");
    }

    private static String clean(String s) {
        if (s == null) {
            return "";
        }
        s = s.trim();
        if (s.indexOf('\n') >= 0 || s.indexOf('\r') >= 0 || s.indexOf('=') >= 0) {
            return "";
        }
        return s;
    }
}
