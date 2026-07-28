package org.telegram.messenger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * A loopback HTTP CONNECT proxy that carries the setup WebView through the
 * relay.
 *
 * The WebView uses the system network stack, not tgnet, so it cannot use the
 * native relay transport at all - and on the networks this product targets,
 * my.telegram.org is blocked, which is exactly where the user has to go to
 * create their api_id. This bridges the two: WebView speaks ordinary CONNECT
 * to 127.0.0.1, and each request is carried to the relay as a tunnel.
 *
 * While this is listening, any app on the device can reach the whitelisted
 * hosts through the customer's subscription, so it is started only for the
 * duration of the setup step and stopped as soon as the step is left. The
 * whitelist is enforced here as well as on the relay - not because the client
 * is trusted (it is open source and trivially patched), but so that a
 * misbehaving WebView cannot quietly send traffic somewhere unexpected.
 */
public class LocalProxy {

    private static final Set<String> ALLOWED = new HashSet<>(Arrays.asList(
            "my.telegram.org",
            "telegram.org",
            "www.telegram.org",
            "core.telegram.org"));

    private final String relayHost;
    private final String relayIp;
    private final int relayPort;
    private final String token;

    private ServerSocket server;
    private Thread acceptor;
    private volatile boolean running;

    public LocalProxy(String relayHost, String relayIp, int relayPort, String token) {
        this.relayHost = relayHost;
        this.relayIp = relayIp;
        this.relayPort = relayPort;
        this.token = token;
    }

    /** @return the loopback port to point the WebView at, or -1 on failure */
    public int start() {
        try {
            server = new ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"));
            running = true;
            acceptor = new Thread(new Runnable() {
                public void run() {
                    acceptLoop();
                }
            }, "relay-localproxy");
            acceptor.setDaemon(true);
            acceptor.start();
            return server.getLocalPort();
        } catch (Throwable t) {
            return -1;
        }
    }

    public void stop() {
        running = false;
        try {
            if (server != null) {
                server.close();
            }
        } catch (Throwable ignore) {
        }
    }

    private void acceptLoop() {
        while (running) {
            final Socket client;
            try {
                client = server.accept();
            } catch (Throwable t) {
                return;         // closed, or we are shutting down
            }
            Thread t = new Thread(new Runnable() {
                public void run() {
                    handle(client);
                }
            }, "relay-localproxy-conn");
            t.setDaemon(true);
            t.start();
        }
    }

    private void handle(Socket client) {
        Socket upstream = null;
        try {
            client.setSoTimeout(20000);
            String request = readRequestLine(client.getInputStream());
            if (request == null) {
                respond(client, "400 Bad Request");
                return;
            }
            String[] parts = request.split(" ");
            if (parts.length < 2 || !"CONNECT".equalsIgnoreCase(parts[0])) {
                // Only CONNECT is supported: everything the setup flow needs is
                // https, and proxying plain http would mean this process could
                // be used to fetch arbitrary URLs.
                respond(client, "405 Method Not Allowed");
                return;
            }
            String hostPort = parts[1];
            int colon = hostPort.lastIndexOf(':');
            String host = colon > 0 ? hostPort.substring(0, colon) : hostPort;
            host = host.toLowerCase(Locale.US);
            if (!ALLOWED.contains(host)) {
                respond(client, "403 Forbidden");
                return;
            }

            upstream = RelayClient.tunnel(relayHost, relayIp, relayPort, token, host, 15000);
            if (upstream == null) {
                respond(client, "502 Bad Gateway");
                return;
            }
            respond(client, "200 Connection Established");
            client.setSoTimeout(0);
            pump(client, upstream);
        } catch (Throwable ignore) {
        } finally {
            closeQuietly(upstream);
            closeQuietly(client);
        }
    }

    /** Read the request line and drain the headers. */
    private String readRequestLine(InputStream in) throws IOException {
        StringBuilder line = new StringBuilder();
        String first = null;
        int c;
        int guard = 0;
        while ((c = in.read()) != -1 && guard++ < 16384) {
            if (c == '\n') {
                String s = line.toString().trim();
                if (first == null) {
                    first = s;
                } else if (s.isEmpty()) {
                    return first;           // end of headers
                }
                line.setLength(0);
            } else if (c != '\r') {
                line.append((char) c);
            }
        }
        return first;
    }

    private void respond(Socket s, String status) {
        try {
            s.getOutputStream().write(("HTTP/1.1 " + status + "\r\n\r\n").getBytes("US-ASCII"));
            s.getOutputStream().flush();
        } catch (Throwable ignore) {
        }
    }

    private void pump(final Socket a, final Socket b) throws IOException {
        Thread up = new Thread(new Runnable() {
            public void run() {
                copy(a, b);
            }
        }, "relay-localproxy-up");
        up.setDaemon(true);
        up.start();
        copy(b, a);
        try {
            up.join(2000);
        } catch (InterruptedException ignore) {
        }
    }

    private void copy(Socket from, Socket to) {
        byte[] buf = new byte[16384];
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (Throwable ignore) {
        } finally {
            closeQuietly(from);
            closeQuietly(to);
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            if (s != null) {
                s.close();
            }
        } catch (Throwable ignore) {
        }
    }
}
