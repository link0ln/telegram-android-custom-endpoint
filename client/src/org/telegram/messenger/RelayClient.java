package org.telegram.messenger;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Locale;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLParameters;

/**
 * Java-side speaker of the relay protocol.
 *
 * Two jobs the native transport cannot do:
 *
 *  - Validate the setup code before the user is sent any further, and read the
 *    subscription status back in a form the UI can show.
 *  - Verify the relay's certificate properly (full chain plus hostname) and
 *    record the SHA-256 of its public key, which the native layer then pins.
 *    The native TLS client runs with verification disabled, so without this
 *    step the bearer token would be exposed to any on-path attacker.
 *
 * Wire format lives in server/wire.py; the two must be changed together.
 */
public class RelayClient {

    public static final int MODE_PING = 0x11;
    public static final int MODE_TUNNEL = 0x10;

    public static final int ST_OK = 0x00;
    public static final int ST_EXPIRED = 0x01;
    public static final int ST_DEVICE_LIMIT = 0x02;
    public static final int ST_SUSPENDED = 0x03;
    public static final int ST_QUOTA = 0x04;
    public static final int ST_BUSY = 0x05;
    public static final int ST_FORBIDDEN_HOST = 0x07;
    public static final int ST_UPSTREAM = 0x08;

    /** No status frame came back: bad token, or the relay is unreachable. The
     *  two are deliberately indistinguishable - an unknown token is masked to
     *  the cover site exactly like a stray probe - so the UI must not claim to
     *  know which happened. */
    public static final int ST_NO_ANSWER = -1;

    private static final byte[] MAGIC3 = {'T', 'G', 'R'};
    private static final int VER_V2 = 0x02;
    private static final byte[] STATUS_MAGIC = {'T', 'G', 'S', '2'};
    private static final int STATUS_HDR_LEN = 10;
    private static final int TLV_CONNECT_HOST = 0x01;
    private static final int TLV_CLIENT_VERSION = 0x03;

    public static class Status {
        public int code = ST_NO_ANSWER;
        public int ttlDays;
        public String json = "";
        /** SHA-256 of the relay certificate's public key, 64 hex chars */
        public String pin = "";

        public boolean ok() {
            return code == ST_OK;
        }
    }

    // ---- base32, matching wire.py -------------------------------------

    private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /** Decode a human-typed token. Tolerates case, spaces, hyphens and the
     *  0/O 1/I 8/B confusions (none of those digits are in the alphabet, so
     *  the repair is unambiguous). Returns null if it is not a valid token. */
    public static byte[] decodeToken(String text) {
        if (text == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(26);
        for (char c : text.trim().toUpperCase(Locale.US).toCharArray()) {
            if (!Character.isLetterOrDigit(c)) {
                continue;
            }
            if (c == '0') c = 'O';
            else if (c == '1') c = 'I';
            else if (c == '8') c = 'B';
            sb.append(c);
        }
        if (sb.length() != 26) {
            return null;
        }
        long buffer = 0;
        int bits = 0;
        byte[] out = new byte[16];
        int n = 0;
        for (int i = 0; i < sb.length(); i++) {
            int v = B32.indexOf(sb.charAt(i));
            if (v < 0) {
                return null;
            }
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                if (n >= 16) {
                    return null;
                }
                out[n++] = (byte) ((buffer >> bits) & 0xFF);
            }
        }
        return n == 16 ? out : null;
    }

    public static byte[] decodeHex(String hex) {
        if (hex == null || (hex.length() & 1) != 0) {
            return null;
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                return null;
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    // ---- setup code ---------------------------------------------------

    public static class SetupCode {
        public String host = "";
        public String ip;          // optional pin, for poisoned-DNS networks
        public String token = "";
    }

    /** Parse "host|TOKEN|CHECK" or "host@ip|TOKEN|CHECK". Returns null if the
     *  checksum does not match, which means the code was mistyped. */
    public static SetupCode parseSetupCode(String text) {
        if (text == null) {
            return null;
        }
        String[] parts = text.trim().split("\\|");
        if (parts.length != 3) {
            return null;
        }
        String hostpart = parts[0].trim();
        String token = parts[1].trim().toUpperCase(Locale.US);
        String check = parts[2].trim().toUpperCase(Locale.US);
        if (!check.equals(setupChecksum(hostpart, token))) {
            return null;
        }
        if (decodeToken(token) == null) {
            return null;
        }
        SetupCode sc = new SetupCode();
        int at = hostpart.indexOf('@');
        sc.host = at >= 0 ? hostpart.substring(0, at) : hostpart;
        sc.ip = at >= 0 ? hostpart.substring(at + 1) : null;
        sc.token = token;
        if (sc.host.isEmpty()) {
            return null;
        }
        return sc;
    }

    private static String setupChecksum(String hostpart, String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest((hostpart + "|" + token).getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            long buffer = 0;
            int bits = 0;
            for (byte b : d) {
                buffer = (buffer << 8) | (b & 0xFF);
                bits += 8;
                while (bits >= 5 && sb.length() < 4) {
                    bits -= 5;
                    sb.append(B32.charAt((int) ((buffer >> bits) & 31)));
                }
                if (sb.length() >= 4) {
                    break;
                }
            }
            return sb.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    // ---- connection ---------------------------------------------------

    /**
     * TLS to the relay with the certificate fully verified against the system
     * trust store and the hostname checked. Connects to `ip` when given, so a
     * poisoned resolver cannot redirect us, while SNI and verification still
     * use the real hostname.
     */
    public static SSLSocket connect(String host, String ip, int timeoutMs) throws IOException {
        Socket raw = new Socket();
        raw.connect(new InetSocketAddress(ip != null && !ip.isEmpty() ? ip : host, 443), timeoutMs);
        raw.setSoTimeout(timeoutMs);
        SSLSocket s = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                .createSocket(raw, host, 443, true);
        SSLParameters p = s.getSSLParameters();
        p.setEndpointIdentificationAlgorithm("HTTPS");
        s.setSSLParameters(p);
        s.startHandshake();
        return s;
    }

    /** SHA-256 over the peer's SubjectPublicKeyInfo - what the native side pins. */
    public static String pinOf(SSLSocket sock) {
        try {
            Certificate[] chain = sock.getSession().getPeerCertificates();
            if (chain == null || chain.length == 0) {
                return "";
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return toHex(md.digest(chain[0].getPublicKey().getEncoded()));
        } catch (Throwable t) {
            return "";
        }
    }

    private static byte[] buildHello(int mode, byte[] token, byte[] device, String connectHost) {
        byte[] ext = new byte[0];
        if (connectHost != null && !connectHost.isEmpty()) {
            byte[] h;
            try {
                h = connectHost.getBytes("US-ASCII");
            } catch (Throwable t) {
                h = new byte[0];
            }
            ext = new byte[2 + h.length];
            ext[0] = (byte) TLV_CONNECT_HOST;
            ext[1] = (byte) h.length;
            System.arraycopy(h, 0, ext, 2, h.length);
        }
        byte[] out = new byte[5 + 16 + 16 + 2 + ext.length];
        int i = 0;
        out[i++] = MAGIC3[0];
        out[i++] = MAGIC3[1];
        out[i++] = MAGIC3[2];
        out[i++] = (byte) VER_V2;
        out[i++] = (byte) mode;
        System.arraycopy(token, 0, out, i, 16);
        i += 16;
        System.arraycopy(device, 0, out, i, 16);
        i += 16;
        out[i++] = (byte) ((ext.length >> 8) & 0xFF);
        out[i++] = (byte) (ext.length & 0xFF);
        System.arraycopy(ext, 0, out, i, ext.length);
        return out;
    }

    private static Status readStatus(InputStream in) throws IOException {
        Status st = new Status();
        DataInputStream d = new DataInputStream(in);
        byte[] hdr = new byte[STATUS_HDR_LEN];
        d.readFully(hdr);
        for (int i = 0; i < 4; i++) {
            if (hdr[i] != STATUS_MAGIC[i]) {
                st.code = ST_NO_ANSWER;
                return st;
            }
        }
        st.code = hdr[4] & 0xFF;
        st.ttlDays = ((hdr[6] & 0xFF) << 8) | (hdr[7] & 0xFF);
        int plen = ((hdr[8] & 0xFF) << 8) | (hdr[9] & 0xFF);
        if (plen > 0 && plen <= 1024) {
            byte[] body = new byte[plen];
            d.readFully(body);
            st.json = new String(body, "UTF-8");
        }
        return st;
    }

    /**
     * Ask the relay about a subscription. Never throws: any failure comes back
     * as ST_NO_ANSWER, because "wrong token" and "blocked network" must look
     * the same to the user - the relay makes them look the same on the wire.
     */
    public static Status ping(String host, String ip, String tokenText, int timeoutMs) {
        Status st = new Status();
        byte[] token = decodeToken(tokenText);
        if (token == null) {
            return st;
        }
        byte[] device = decodeHex(DeviceId.get());
        SSLSocket sock = null;
        try {
            sock = connect(host, ip, timeoutMs);
            st.pin = pinOf(sock);
            OutputStream out = sock.getOutputStream();
            out.write(buildHello(MODE_PING, token, device, null));
            out.flush();
            Status got = readStatus(sock.getInputStream());
            got.pin = st.pin;
            return got;
        } catch (Throwable t) {
            return st;
        } finally {
            try {
                if (sock != null) {
                    sock.close();
                }
            } catch (Throwable ignore) {
            }
        }
    }

    /**
     * Open a tunnel to a whitelisted host through the relay. Returns a socket
     * positioned right after the relay's acknowledgement, ready to carry the
     * caller's own TLS session, or null if the relay refused.
     */
    public static SSLSocket tunnel(String host, String ip, String tokenText,
                                   String targetHost, int timeoutMs) {
        byte[] token = decodeToken(tokenText);
        if (token == null) {
            return null;
        }
        byte[] device = decodeHex(DeviceId.get());
        SSLSocket sock = null;
        try {
            sock = connect(host, ip, timeoutMs);
            OutputStream out = sock.getOutputStream();
            out.write(buildHello(MODE_TUNNEL, token, device, targetHost));
            out.flush();
            Status st = readStatus(sock.getInputStream());
            if (st.code != ST_OK) {
                sock.close();
                return null;
            }
            sock.setSoTimeout(0);
            return sock;
        } catch (Throwable t) {
            try {
                if (sock != null) {
                    sock.close();
                }
            } catch (Throwable ignore) {
            }
            return null;
        }
    }
}
