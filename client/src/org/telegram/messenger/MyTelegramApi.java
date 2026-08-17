package org.telegram.messenger;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Creates the user's own api_id / api_hash by talking to my.telegram.org
 * directly, with plain HTTP requests carried through the relay tunnel.
 *
 * No WebView: the three endpoints this needs are a form post each, and the
 * site answers them without JavaScript or a bot challenge. That removes the
 * whole WebView/proxy-override layer, and with it a pile of failure modes -
 * a stale system WebView, a process-wide proxy override left behind, cookies
 * outliving the screen.
 *
 * Two TLS sessions are stacked here. The outer one is ours, to the relay, and
 * carries the subscription token. The inner one is the user's, to
 * my.telegram.org, and is verified in full (hostname included) - the relay
 * operator is not trusted with the account's login code any more than a
 * censor is.
 *
 * The one thing that cannot be automated: my.telegram.org states plainly that
 * it "will send you a confirmation code via Telegram (not SMS)". There is no
 * SMS or email fallback, so the user has to read one message from a Telegram
 * that can still reach the network. The screens say so before asking for a
 * number rather than after.
 */
public class MyTelegramApi {

    public static final String HOST = "my.telegram.org";

    private static final String UA =
            "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) "
                    + "Chrome/120.0.0.0 Mobile Safari/537.36";
    private static final int TIMEOUT_MS = 25000;
    private static final int MAX_BODY = 512 * 1024;

    /** Where the relay is, so every call does not have to re-read config. */
    public static class Endpoint {
        public String host;
        public String ip;
        public int port;
        public String token;

        public static Endpoint fromConfig() {
            Endpoint e = new Endpoint();
            e.host = CustomConfig.getEndpoint();
            e.ip = CustomConfig.getEndpointIp();
            e.port = CustomConfig.getEndpointPort();
            e.token = CustomConfig.getToken();
            return e;
        }
    }

    public static class Result {
        public boolean ok;
        /** Already phrased for a human; empty when ok. */
        public String error = "";
        public String randomHash = "";
        public String cookie = "";
        public int apiId;
        public String apiHash = "";
        /** /apps showed the creation form instead of an existing app. */
        public boolean needsCreate;
        public String createHash = "";

        static Result fail(String message) {
            Result r = new Result();
            r.error = message;
            return r;
        }
    }

    // ------------------------------------------------------------- steps ----

    /** Ask my.telegram.org to send the confirmation code. */
    public static Result sendCode(Endpoint ep, String phone) {
        Resp r = post(ep, "/auth/send_password", "phone=" + enc(normalisePhone(phone)), null);
        if (r == null) {
            return Result.fail("Couldn't reach my.telegram.org through the relay.");
        }
        String hash = firstGroup(P_RANDOM_HASH, r.body);
        if (hash == null) {
            return Result.fail(describe(r.body,
                    "my.telegram.org didn't accept that number."));
        }
        Result out = new Result();
        out.ok = true;
        out.randomHash = hash;
        return out;
    }

    /** Exchange the code for a session cookie. */
    public static Result login(Endpoint ep, String phone, String randomHash, String code) {
        String body = "phone=" + enc(normalisePhone(phone))
                + "&random_hash=" + enc(randomHash)
                + "&password=" + enc(code.trim());
        Resp r = post(ep, "/auth/login", body, null);
        if (r == null) {
            return Result.fail("Couldn't reach my.telegram.org through the relay.");
        }
        String cookie = cookieOf(r);
        if (cookie.isEmpty()) {
            return Result.fail(describe(r.body, "That code wasn't accepted."));
        }
        Result out = new Result();
        out.ok = true;
        out.cookie = cookie;
        return out;
    }

    /** Read the account's application, or report that one must be created. */
    public static Result fetchApp(Endpoint ep, String cookie) {
        Resp r = get(ep, "/apps", cookie);
        if (r == null) {
            return Result.fail("Couldn't reach my.telegram.org through the relay.");
        }
        if (r.status == 302 || r.body.contains("/auth/login")) {
            return Result.fail("The my.telegram.org session expired - start again.");
        }

        String page = stripHiddenInputs(r.body);
        String id = firstGroup(P_API_ID, page);
        String hash = firstGroup(P_API_HASH, page);
        if (id != null && hash != null) {
            Result out = new Result();
            out.ok = true;
            try {
                out.apiId = Integer.parseInt(id);
            } catch (NumberFormatException e) {
                return Result.fail("my.telegram.org returned an api_id we couldn't read.");
            }
            out.apiHash = hash;
            return out;
        }

        // No app yet: the creation form carries the CSRF-ish hash we must echo.
        String createHash = firstGroup(P_FORM_HASH, r.body);
        if (createHash != null) {
            Result out = new Result();
            out.ok = true;
            out.needsCreate = true;
            out.createHash = createHash;
            return out;
        }
        return Result.fail("my.telegram.org returned a page we didn't recognise.");
    }

    /**
     * Register the application. One per account is all Telegram allows, so
     * this runs once and every later setup reads the same values back.
     */
    public static Result createApp(Endpoint ep, String cookie, String createHash,
                                   String title, String shortName) {
        String body = "hash=" + enc(createHash)
                + "&app_title=" + enc(title)
                + "&app_shortname=" + enc(shortName)
                + "&app_url=" + enc("")
                + "&app_platform=android"
                + "&app_desc=" + enc("");
        Resp r = post(ep, "/apps/create", body, cookie);
        if (r == null) {
            return Result.fail("Couldn't reach my.telegram.org through the relay.");
        }
        if (r.body.contains("ERROR") && r.body.length() < 400) {
            return Result.fail(describe(r.body, "my.telegram.org refused to create the app."));
        }
        // The create response is not the app page; read it back properly.
        return fetchApp(ep, cookie);
    }

    /** The whole sequence after the code has been entered. */
    public static Result finishLogin(Endpoint ep, String phone, String randomHash,
                                     String code, String appTitle, String appShort) {
        Result login = login(ep, phone, randomHash, code);
        if (!login.ok) {
            return login;
        }
        Result app = fetchApp(ep, login.cookie);
        if (app.ok && app.needsCreate) {
            app = createApp(ep, login.cookie, app.createHash, appTitle, appShort);
        }
        return app;
    }

    // ------------------------------------------------------------ parsing ---

    private static final Pattern P_RANDOM_HASH =
            Pattern.compile("\"random_hash\"\\s*:\\s*\"([0-9a-zA-Z]{8,64})\"");
    private static final Pattern P_FORM_HASH = Pattern.compile(
            "name=[\"']hash[\"'][^>]*value=[\"']([0-9a-f]{16,64})[\"']");
    private static final Pattern P_HIDDEN = Pattern.compile(
            "<input[^>]*type=[\"']hidden[\"'][^>]*>", Pattern.CASE_INSENSITIVE);
    /**
     * Anchored on the label, because the page also carries 32-hex values that
     * are not the api_hash - the login form's random_hash and the create
     * form's hash have exactly the same shape. Hidden inputs are stripped
     * before these run, which removes both.
     */
    private static final Pattern P_API_ID = Pattern.compile(
            "api_id[\\s\\S]{0,200}?>\\s*(\\d{5,10})\\s*<", Pattern.CASE_INSENSITIVE);
    private static final Pattern P_API_HASH = Pattern.compile(
            "api_hash[\\s\\S]{0,200}?>\\s*([0-9a-f]{32})\\s*<", Pattern.CASE_INSENSITIVE);
    private static final Pattern P_ERROR = Pattern.compile(
            "<p[^>]*class=[\"'][^\"']*(?:error|alert)[^\"']*[\"'][^>]*>([^<]{3,160})<");

    private static String stripHiddenInputs(String html) {
        return P_HIDDEN.matcher(html).replaceAll(" ");
    }

    private static String firstGroup(Pattern p, String text) {
        if (text == null) {
            return null;
        }
        Matcher m = p.matcher(text);
        return m.find() ? m.group(1) : null;
    }

    /** Prefer the site's own words when it bothered to give any. */
    private static String describe(String body, String fallback) {
        String said = firstGroup(P_ERROR, body);
        if (said != null) {
            return said.trim();
        }
        String trimmed = body == null ? "" : body.trim();
        if (trimmed.length() > 0 && trimmed.length() < 120
                && !trimmed.startsWith("<")) {
            return trimmed;
        }
        return fallback;
    }

    static String normalisePhone(String raw) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c >= '0' && c <= '9') {
                sb.append(c);
            }
        }
        return "+" + sb;
    }

    private static String enc(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (Throwable t) {
            return s;
        }
    }

    private static String cookieOf(Resp r) {
        List<String> keep = new ArrayList<>();
        for (String h : r.headers) {
            String lower = h.toLowerCase();
            if (!lower.startsWith("set-cookie:")) {
                continue;
            }
            String v = h.substring(h.indexOf(':') + 1).trim();
            int semi = v.indexOf(';');
            String pair = semi >= 0 ? v.substring(0, semi) : v;
            // A deletion looks like a set; treat it as the failure it is.
            if (pair.startsWith("stel_token=") && !pair.endsWith("=deleted")
                    && pair.length() > "stel_token=".length() + 4) {
                keep.add(pair);
            }
        }
        return join(keep);
    }

    private static String join(List<String> parts) {
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append(p);
        }
        return sb.toString();
    }

    // ----------------------------------------------------------- transport --

    static class Resp {
        int status;
        List<String> headers = new ArrayList<>();
        String body = "";
    }

    private static Resp get(Endpoint ep, String path, String cookie) {
        return exchange(ep, "GET", path, null, cookie);
    }

    private static Resp post(Endpoint ep, String path, String body, String cookie) {
        return exchange(ep, "POST", path, body, cookie);
    }

    /**
     * One request, one connection. Connection reuse would be nice, but the
     * relay meters and rate-limits tunnels per token, and these are three
     * small requests in a row - simplicity wins.
     */
    private static Resp exchange(Endpoint ep, String method, String path,
                                 String body, String cookie) {
        SSLSocket tun = null;
        SSLSocket tls = null;
        try {
            tun = RelayClient.tunnel(ep.host, ep.ip, ep.port, ep.token, HOST, TIMEOUT_MS);
            if (tun == null) {
                return null;
            }
            tls = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                    .createSocket(tun, HOST, 443, true);
            // Our TLS to the relay says nothing about this one: verify the
            // hostname, or the relay could read the account's login code.
            SSLParameters params = tls.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            tls.setSSLParameters(params);
            tls.setSoTimeout(TIMEOUT_MS);
            tls.startHandshake();

            StringBuilder head = new StringBuilder();
            head.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
            head.append("Host: ").append(HOST).append("\r\n");
            head.append("User-Agent: ").append(UA).append("\r\n");
            head.append("Accept: */*\r\n");
            if (cookie != null && !cookie.isEmpty()) {
                head.append("Cookie: ").append(cookie).append("\r\n");
            }
            if (body != null) {
                head.append("Content-Type: application/x-www-form-urlencoded\r\n");
                head.append("Content-Length: ").append(body.getBytes("UTF-8").length).append("\r\n");
                head.append("Referer: https://").append(HOST).append("/auth\r\n");
                head.append("X-Requested-With: XMLHttpRequest\r\n");
            }
            head.append("Connection: close\r\n\r\n");

            OutputStream out = tls.getOutputStream();
            out.write(head.toString().getBytes("UTF-8"));
            if (body != null) {
                out.write(body.getBytes("UTF-8"));
            }
            out.flush();

            byte[] raw = readAll(tls.getInputStream());
            return parse(raw);
        } catch (Throwable t) {
            return null;
        } finally {
            closeQuietly(tls);
            closeQuietly(tun);
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[16384];
        while (buf.size() < MAX_BODY) {
            int n = in.read(chunk);
            if (n < 0) {
                break;
            }
            buf.write(chunk, 0, n);
        }
        return buf.toByteArray();
    }

    private static Resp parse(byte[] raw) throws Exception {
        String all = new String(raw, "UTF-8");
        int split = all.indexOf("\r\n\r\n");
        if (split < 0) {
            return null;
        }
        Resp r = new Resp();
        String[] lines = all.substring(0, split).split("\r\n");
        if (lines.length > 0) {
            String[] bits = lines[0].split(" ");
            if (bits.length > 1) {
                try {
                    r.status = Integer.parseInt(bits[1]);
                } catch (NumberFormatException ignore) {
                }
            }
        }
        for (int i = 1; i < lines.length; i++) {
            r.headers.add(lines[i]);
        }
        String body = all.substring(split + 4);
        r.body = isChunked(r.headers) ? dechunk(body) : body;
        return r;
    }

    private static boolean isChunked(List<String> headers) {
        for (String h : headers) {
            if (h.toLowerCase().startsWith("transfer-encoding:")
                    && h.toLowerCase().contains("chunked")) {
                return true;
            }
        }
        return false;
    }

    private static String dechunk(String body) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < body.length()) {
            int eol = body.indexOf("\r\n", i);
            if (eol < 0) {
                break;
            }
            String sizeLine = body.substring(i, eol).trim();
            int semi = sizeLine.indexOf(';');
            if (semi >= 0) {
                sizeLine = sizeLine.substring(0, semi);
            }
            int size;
            try {
                size = Integer.parseInt(sizeLine.trim(), 16);
            } catch (NumberFormatException e) {
                break;
            }
            if (size == 0) {
                break;
            }
            int start = eol + 2;
            int end = Math.min(start + size, body.length());
            sb.append(body, start, end);
            i = end + 2;
        }
        return sb.toString();
    }

    private static void closeQuietly(java.io.Closeable c) {
        try {
            if (c != null) {
                c.close();
            }
        } catch (Throwable ignore) {
        }
    }
}
