package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.io.FileWriter;
import java.net.InetAddress;

/**
 * Runtime configuration entered by the user on first launch:
 * api_id, api_hash and the relay endpoint (hostname). No values are baked in.
 */
public class CustomConfig {

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

    public static boolean isConfigured() {
        return getApiId() != 0
                && !getApiHash().isEmpty()
                && !getEndpoint().isEmpty()
                && !getEndpointIp().isEmpty();
    }

    public static void save(int apiId, String apiHash, String endpoint, String endpointIp) {
        prefs().edit()
                .putInt("api_id", apiId)
                .putString("api_hash", apiHash == null ? "" : apiHash.trim())
                .putString("endpoint", endpoint == null ? "" : endpoint.trim())
                .putString("endpoint_ip", endpointIp == null ? "" : endpointIp.trim())
                .commit();   // synchronous: must be on disk before ConfigActivity restarts the process
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

    /** Write "ip\nsni" to &lt;configPath&gt;/relay.cfg for the native layer to read at init(). */
    public static void writeRelayFile(String configPath) {
        try {
            String ip = getEndpointIp();
            String sni = getEndpoint();
            File f = new File(configPath, "relay.cfg");
            if (ip == null || ip.isEmpty() || sni == null || sni.isEmpty()) {
                if (f.exists()) {
                    f.delete();
                }
                return;
            }
            FileWriter w = new FileWriter(f, false);
            w.write(ip + "\n" + sni + "\n");
            w.close();
        } catch (Throwable ignore) {
        }
    }
}
