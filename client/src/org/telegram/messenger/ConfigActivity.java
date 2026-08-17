package org.telegram.messenger;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.ValueCallback;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.webkit.ProxyConfig;
import androidx.webkit.ProxyController;
import androidx.webkit.WebViewFeature;

import java.util.Locale;

/**
 * Setup and renewal, as a few swapped views inside one Activity.
 *
 * Nothing is baked into the binary: the user brings their own api_id/api_hash
 * and, when the relay charges for access, a setup code.
 *
 * The awkward constraint the whole flow is shaped around: my.telegram.org sends
 * its login code as a Telegram message, never by SMS. So creating an api_id
 * requires an account that is already signed in *somewhere else*. We cannot
 * remove that requirement, so the copy states it up front instead of letting
 * people discover it halfway through.
 */
public class ConfigActivity extends Activity {

    public static final String EXTRA_STEP = "step";
    public static final String STEP_CODE = "code";
    public static final String STEP_API = "api";
    public static final String STEP_RENEWAL = "renewal";

    private LinearLayout root;
    private LocalProxy proxy;
    private WebView webView;
    private boolean proxyOverrideSet;
    private boolean harvested;

    // what the flow has gathered so far
    private String host = "";
    private String ip = "";
    private int port = 443;
    private String token = "";
    private String pin = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView scroll = new ScrollView(this);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(20);
        root.setPadding(pad, pad, pad, pad);
        scroll.addView(root);
        setContentView(scroll);

        host = CustomConfig.getEndpoint();
        ip = CustomConfig.getEndpointIp();
        port = CustomConfig.getEndpointPort();
        token = CustomConfig.getToken();
        pin = CustomConfig.getEndpointPin();

        String step = getIntent() != null ? getIntent().getStringExtra(EXTRA_STEP) : null;
        if (STEP_RENEWAL.equals(step) || (RelayStatus.isBlocking() && CustomConfig.hasEndpoint())) {
            showRenewal();
        } else if (STEP_API.equals(step) || (CustomConfig.hasEndpoint() && !CustomConfig.isConfigured())) {
            showApiStep();
        } else if (STEP_CODE.equals(step) || !CustomConfig.isConfigured()) {
            showCodeStep();
        } else {
            // Already set up. Opening the launcher icon used to drop straight
            // into an empty setup form, which reads as "my settings are gone".
            showConfigured();
        }
    }

    @Override
    protected void onDestroy() {
        stopProxy();
        super.onDestroy();
    }

    // ------------------------------------------------------------ step 1 ----

    private void showCodeStep() {
        root.removeAllViews();
        title("Set up");
        body("Paste the setup code you were given.\n\n"
                + "Running your own relay instead? Type its host and nothing else.");

        // One field, not two. The setup code already carries the host, so a
        // separate host box next to it was dead weight for anyone with a code -
        // and worse, the pair read as one two-part form, inviting people to
        // split the code across them.
        final EditText codeEdit = edit("setup code, or your own relay host", InputType.TYPE_CLASS_TEXT);
        if (token.isEmpty()) {
            codeEdit.setText(host);
        }
        final TextView status = note("");

        final Button next = button("Continue");
        next.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                String in = codeEdit.getText().toString().trim();
                String h, t = "";
                int p = 443;
                String pinnedIp = null;
                if (in.isEmpty()) {
                    status.setText("Paste your setup code, or the host of your own relay.");
                    return;
                }
                if (in.indexOf('|') >= 0) {
                    RelayClient.SetupCode sc = RelayClient.parseSetupCode(in);
                    if (sc == null) {
                        status.setText("That code doesn't look right - check for a missing character.");
                        return;
                    }
                    h = sc.host;
                    t = sc.token;
                    p = sc.port;
                    pinnedIp = sc.ip;
                } else if (looksLikeBareToken(in)) {
                    // A token on its own has no host to connect to, and telling
                    // someone "can't look up LUQ6RC... on this network" would be
                    // a baffling way to say so.
                    status.setText("That is only the token. Paste the whole setup code, "
                            + "including the host and the check letters.");
                    return;
                } else {
                    h = in;
                    int colon = h.lastIndexOf(':');
                    if (colon > 0) {
                        try {
                            int typed = Integer.parseInt(h.substring(colon + 1));
                            if (typed > 0 && typed <= 65535) {
                                p = typed;
                                h = h.substring(0, colon);
                            }
                        } catch (NumberFormatException ignore) {
                        }
                    }
                }
                next.setEnabled(false);
                next.setText("Checking " + h + " ...");
                validate(h, p, t, pinnedIp, next, status, "Continue");
            }
        });

        footer();
    }

    /**
     * Is this the token half of a setup code, pasted without its host?
     * 16 random bytes in base32 is 26 characters; we print it with a dash in
     * the middle and accept the digits the decoder repairs (0/1/8).
     */
    private static boolean looksLikeBareToken(String s) {
        String t = s.replace("-", "").replace(" ", "").toUpperCase(Locale.US);
        if (t.length() != 26) {
            return false;
        }
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')
                    || c == '0' || c == '1' || c == '8';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private void validate(final String h, final int p, final String t, final String pinnedIp,
                          final Button next, final TextView status, final String label) {
        new Thread(new Runnable() {
            public void run() {
                final String resolved = pinnedIp != null && !pinnedIp.isEmpty()
                        ? pinnedIp : CustomConfig.resolve(h);
                if (resolved == null) {
                    ui(next, status, label, "Can't look up " + h + " on this network.");
                    return;
                }
                if (t.isEmpty()) {
                    // self-hosted relay: there is nothing to validate against
                    accept(h, resolved, p, "", "");
                    return;
                }
                RelayClient.Status st = RelayClient.ping(h, resolved, p, t, 12000);
                if (st.code == RelayClient.ST_OK) {
                    // the relay just told us the subscription is fine, so drop
                    // any stale verdict before the restart reads it
                    RelayStatus.markOk(st.ttlDays);
                    accept(h, resolved, p, t, st.pin);
                    return;
                }
                ui(next, status, label, describe(st.code));
            }
        }).start();
    }

    private void accept(final String h, final String resolvedIp, final int p,
                        final String t, final String newPin) {
        host = h;
        ip = resolvedIp;
        port = p;
        token = t;
        pin = newPin;
        CustomConfig.saveEndpoint(h, resolvedIp, p, t, newPin);
        runOnUiThread(new Runnable() {
            public void run() {
                if (CustomConfig.isConfigured()) {
                    // Renewal, or a re-run of setup by someone who already has
                    // their keys: there is nothing left to ask, so apply it.
                    restartApp();
                } else {
                    showApiStep();
                }
            }
        });
    }

    private void ui(final Button next, final TextView status,
                    final String label, final String message) {
        runOnUiThread(new Runnable() {
            public void run() {
                next.setEnabled(true);
                next.setText(label);
                status.setText(message);
            }
        });
    }

    /**
     * Say what happened, and only what we actually know.
     *
     * ST_NO_ANSWER must not become "wrong code": the relay masks an unknown
     * token to its cover site, so a bad code and a blocked network look
     * identical from here. A confident wrong answer would send people to fix
     * the wrong thing.
     */
    private String describe(int code) {
        switch (code) {
            case RelayClient.ST_EXPIRED:
                return "This subscription has expired. Renew it, then try again.";
            case RelayClient.ST_DEVICE_LIMIT:
                return "This code is already in use on the maximum number of devices. "
                        + "This device is " + DeviceId.shortForm() + ".";
            case RelayClient.ST_SUSPENDED:
                return "This subscription is not active.";
            case RelayClient.ST_QUOTA:
                return "This subscription is over its traffic quota.";
            case RelayClient.ST_BUSY:
                return "The relay is busy. Try again in a minute.";
            default:
                return "Couldn't set up with this code on this network. Check the code, "
                        + "or try mobile data instead of Wi-Fi.";
        }
    }

    // ------------------------------------------------------------ step 2 ----

    private void showApiStep() {
        root.removeAllViews();
        title("Your API keys");
        body("Telegram requires every client to use API keys from a personal account. "
                + "You create them once at my.telegram.org.\n\n"
                + "Before you start: my.telegram.org sends its confirmation code as a "
                + "Telegram message, not an SMS. You need Telegram already signed in "
                + "somewhere else - another phone, a desktop, or web.telegram.org - to "
                + "read that code.");

        if (CustomConfig.getApiId() != 0) {
            note("Currently set: api_id " + CustomConfig.getApiId());
        }

        Button auto = button("Set up automatically");
        auto.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showPhoneStep();
            }
        });

        Button manual = button("I already have api_id and api_hash");
        manual.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showManualApiStep();
            }
        });

        Button stuck = button("I have no other device signed in");
        stuck.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showStuckStep();
            }
        });

        footer();
    }

    // --------------------------------------------- automatic: no WebView ----

    /**
     * Ask for the number my.telegram.org should log in with. The requests go
     * out as plain HTTP through the relay tunnel, so this screen and the next
     * are the entire "automatic" path - no browser involved.
     */
    private void showPhoneStep() {
        root.removeAllViews();
        title("Create your keys");
        body("Enter the phone number of your Telegram account. We will sign in to "
                + "my.telegram.org through your relay and take the api_id and "
                + "api_hash it issues for you.\n\n"
                + "my.telegram.org sends its code as a Telegram message, never as an "
                + "SMS. You need Telegram reachable somewhere else - another phone, a "
                + "desktop, or web.telegram.org - to read that one message.");

        final EditText phoneEdit = edit("+7 900 000 00 00", InputType.TYPE_CLASS_PHONE);
        final TextView status = note("");

        final Button next = button("Send code");
        next.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                final String phone = phoneEdit.getText().toString().trim();
                if (phone.replaceAll("[^0-9]", "").length() < 7) {
                    status.setText("Enter the number in international format.");
                    return;
                }
                next.setEnabled(false);
                next.setText("Sending ...");
                new Thread(new Runnable() {
                    public void run() {
                        final MyTelegramApi.Result r = MyTelegramApi.sendCode(
                                MyTelegramApi.Endpoint.fromConfig(), phone);
                        runOnUiThread(new Runnable() {
                            public void run() {
                                if (r.ok) {
                                    showMtCodeStep(phone, r.randomHash);
                                } else {
                                    next.setEnabled(true);
                                    next.setText("Send code");
                                    status.setText(r.error);
                                }
                            }
                        });
                    }
                }).start();
            }
        });

        Button manual = button("I already have api_id and api_hash");
        manual.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showManualApiStep();
            }
        });

        Button stuck = button("I can't receive that code");
        stuck.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showStuckStep();
            }
        });

        footer();
    }

    /** Second screen: the my.telegram.org code, then keys, then restart. */
    private void showMtCodeStep(final String phone, final String randomHash) {
        root.removeAllViews();
        title("Confirmation code");
        body("my.telegram.org sent a code to " + phone + " as a Telegram message.\n\n"
                + "Open Telegram wherever it still works and read it there. The "
                + "message arrives as soon as any of your clients connects, so it is "
                + "fine to fetch it in a minute.");

        // my.telegram.org's code is alphanumeric, not a PIN: a number keypad
        // simply cannot type it. No suggestions or autocapitalisation either,
        // since the keyboard would happily "correct" a random string.
        final EditText codeEdit = edit("code", InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        final TextView status = note("");

        final Button next = button("Continue");
        next.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                final String code = codeEdit.getText().toString().trim();
                if (code.isEmpty()) {
                    status.setText("Enter the code from that message.");
                    return;
                }
                next.setEnabled(false);
                next.setText("Signing in ...");
                new Thread(new Runnable() {
                    public void run() {
                        final MyTelegramApi.Result r = MyTelegramApi.finishLogin(
                                MyTelegramApi.Endpoint.fromConfig(), phone, randomHash,
                                code, appTitle(), appShortName());
                        runOnUiThread(new Runnable() {
                            public void run() {
                                if (r.ok && r.apiId != 0 && r.apiHash.length() == 32) {
                                    CustomConfig.saveApiCredentials(r.apiId, r.apiHash);
                                    finishSetup();
                                    return;
                                }
                                next.setEnabled(true);
                                next.setText("Continue");
                                status.setText(r.error.isEmpty()
                                        ? "Couldn't read the keys off my.telegram.org."
                                        : r.error);
                            }
                        });
                    }
                }).start();
            }
        });

        Button again = button("Send the code again");
        again.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showPhoneStep();
            }
        });

        Button manual = button("Enter api_id / api_hash manually");
        manual.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showManualApiStep();
            }
        });

        footer();
    }

    /**
     * Telegram allows one application per account and shows its title in the
     * account's own session list, so keep it plain and stable rather than
     * naming this build.
     */
    private String appTitle() {
        return "Telegram Android";
    }

    private String appShortName() {
        // 5-32 chars, letters and digits only.
        String d = DeviceId.get();
        String tail = d != null && d.length() >= 6 ? d.substring(0, 6) : "client";
        return "tgclient" + tail;
    }

    private void showStuckStep() {
        root.removeAllViews();
        title("Reading the code");
        body("my.telegram.org will only send the confirmation code into Telegram, so "
                + "one signed-in session is unavoidable. Ways around it:\n\n"
                + "1. Sign in at web.telegram.org from any network where Telegram "
                + "works - a friend's Wi-Fi, a hotspot, a VPN you already have.\n\n"
                + "2. Use a computer or tablet where Telegram still works.\n\n"
                + "3. Ask someone you trust to run the my.telegram.org steps while "
                + "you read the code to them.\n\n"
                + "Your subscription clock is already running, but this screen is "
                + "always reachable from the \"Relay Setup\" icon on your home screen.");
        Button back = button("Back");
        back.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showApiStep();
            }
        });
        footer();
    }

    private void showManualApiStep() {
        root.removeAllViews();
        title("Enter API keys");
        body("From https://my.telegram.org/apps.");
        final EditText idEdit = edit("api_id (number)", InputType.TYPE_CLASS_NUMBER);
        final EditText hashEdit = edit("api_hash (32 characters)", InputType.TYPE_CLASS_TEXT);
        if (CustomConfig.getApiId() != 0) {
            idEdit.setText(String.valueOf(CustomConfig.getApiId()));
        }
        hashEdit.setText(CustomConfig.getApiHash());
        final TextView status = note("");

        Button save = button("Save & connect");
        save.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                int id = 0;
                try {
                    id = Integer.parseInt(idEdit.getText().toString().trim());
                } catch (Exception ignore) {
                }
                String hash = hashEdit.getText().toString().trim();
                if (id == 0 || hash.length() != 32) {
                    status.setText("api_id is 5-10 digits and api_hash is 32 characters.");
                    return;
                }
                CustomConfig.saveApiCredentials(id, hash);
                finishSetup();
            }
        });

        Button back = button("Back");
        back.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showApiStep();
            }
        });

        // Last resort. The direct requests do the same job without a browser,
        // but if my.telegram.org changes its forms this still lets someone
        // through by hand, on the same tunnel.
        if (!CustomConfig.getToken().isEmpty()
                && WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            Button web = button("Open my.telegram.org in the app");
            web.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    showWebViewStep();
                }
            });
        }
        footer();
    }

    // ------------------------------------------------------------ step 3 ----

    private void showWebViewStep() {
        root.removeAllViews();
        title("my.telegram.org");
        final TextView status = note("Starting a tunnel through your relay...");

        Button manual = button("Enter manually instead");
        manual.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                stopProxy();
                showManualApiStep();
            }
        });

        if (token.isEmpty()) {
            // Self-hosted relay: the tunnel needs a subscription token, so
            // there is nothing to route through. Go straight out instead of
            // dead-ending on a proxy that cannot be built.
            status.setText("Opening my.telegram.org directly - this relay has no "
                    + "subscription to tunnel through, so it needs a network where "
                    + "the site is reachable.");
            openWebView();
            return;
        }

        proxy = new LocalProxy(host, ip, port, token);
        final int localPort = proxy.start();
        if (localPort <= 0) {
            status.setText("Couldn't start the local tunnel. Use manual entry.");
            return;
        }

        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            status.setText("This device's WebView can't be pointed at a proxy. Use manual entry.");
            return;
        }

        ProxyConfig cfg = new ProxyConfig.Builder()
                .addProxyRule("127.0.0.1:" + localPort)
                .build();
        ProxyController.getInstance().setProxyOverride(cfg, new java.util.concurrent.Executor() {
            public void execute(Runnable r) {
                runOnUiThread(r);
            }
        }, new Runnable() {
            public void run() {
                proxyOverrideSet = true;
                status.setText("Sign in with your phone number. The code arrives as a "
                        + "Telegram message on your other device.");
                openWebView();
            }
        });
    }

    private void openWebView() {
        webView = new WebView(this);
        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(520));
        webView.setLayoutParams(lp);
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                harvest();
            }
        });
        root.addView(webView, 2);
        webView.loadUrl(MyTelegramExtractor.URL_APPS);
    }

    private void harvest() {
        if (webView == null) {
            return;
        }
        webView.evaluateJavascript(MyTelegramExtractor.SCRIPT_PREFILL, null);
        webView.evaluateJavascript(MyTelegramExtractor.SCRIPT, new ValueCallback<String>() {
            public void onReceiveValue(String value) {
                final MyTelegramExtractor.Result r = MyTelegramExtractor.parse(value);
                if (!r.complete() || harvested) {
                    return;
                }
                harvested = true;
                CustomConfig.saveApiCredentials(r.apiId, r.apiHash);
                // Defer: we are inside the WebView's own JS callback, and
                // tearing it down from there crashes. post() runs this after
                // the callback has returned.
                root.post(new Runnable() {
                    public void run() {
                        showFoundStep(r.apiId);   // detaches the WebView
                        stopProxy();              // now safe to destroy it
                    }
                });
            }
        });
    }

    private void showFoundStep(int apiId) {
        root.removeAllViews();
        title("Found your API keys");
        body("api_id " + apiId + " and its api_hash were read from your account.\n\n"
                + "The app will restart to apply the settings.");
        Button go = button("Save & connect");
        go.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                finishSetup();
            }
        });
        footer();
    }

    // --------------------------------------------------------- configured ---

    /** What the launcher icon shows once everything is set up. */
    private void showConfigured() {
        root.removeAllViews();
        title("Relay");
        body(RelayStatus.describe());

        String tok = CustomConfig.getToken();
        note("endpoint   " + host + (port != 443 ? ":" + port : "")
                + "\naddress    " + ip
                + "\nsubscription  " + (tok.isEmpty()
                        ? "none (self-hosted relay)"
                        : tok.substring(0, Math.min(6, tok.length())) + "…")
                + "\napi_id     " + CustomConfig.getApiId()
                + "\npinned     " + (CustomConfig.getEndpointPin().isEmpty() ? "no" : "yes"));

        Button open = button("Open Telegram");
        open.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                startActivity(new Intent(ConfigActivity.this, org.telegram.ui.LaunchActivity.class));
                finish();
            }
        });

        Button code = button("Enter a different setup code");
        code.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showCodeStep();
            }
        });

        Button keys = button("Change api_id / api_hash");
        keys.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showManualApiStep();
            }
        });

        footer();
    }

    // ----------------------------------------------------------- renewal ----

    private void showRenewal() {
        root.removeAllViews();
        title("Subscription");
        body(RelayStatus.describe() + "\n\n"
                + "Enter a new setup code below once you have renewed.");
        note("device " + DeviceId.shortForm()
                + (host.isEmpty() ? "" : "   endpoint " + host));

        final EditText codeEdit = edit("new setup code", InputType.TYPE_CLASS_TEXT);
        final TextView status = note("");

        final Button check = button("Check again");
        check.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                String code = codeEdit.getText().toString().trim();
                String h = host;
                int p = port;
                String t = token;
                String pinnedIp = null;
                if (!code.isEmpty()) {
                    RelayClient.SetupCode sc = RelayClient.parseSetupCode(code);
                    if (sc == null) {
                        status.setText("That code doesn't look right.");
                        return;
                    }
                    h = sc.host;
                    p = sc.port;
                    t = sc.token;
                    pinnedIp = sc.ip;
                }
                check.setEnabled(false);
                check.setText("Checking ...");
                validate(h, p, t, pinnedIp, check, status, "Check again");
            }
        });

        Button plain = button("Remove relay, use plain Telegram");
        plain.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                CustomConfig.clear();
                restartApp();
            }
        });
        footer();
    }

    // ------------------------------------------------------------ shared ----

    private void finishSetup() {
        stopProxy();
        if (!CustomConfig.isConfigured()) {
            Toast.makeText(this, "Still missing api_id / api_hash.", Toast.LENGTH_LONG).show();
            showApiStep();
            return;
        }
        restartApp();
    }

    private void stopProxy() {
        try {
            if (webView != null) {
                webView.stopLoading();
                CookieManager.getInstance().removeAllCookies(null);
                ViewGroup parent = (ViewGroup) webView.getParent();
                if (parent != null) {
                    parent.removeView(webView);   // destroying an attached WebView crashes
                }
                webView.destroy();
                webView = null;
            }
        } catch (Throwable ignore) {
        }
        try {
            // The override is process-wide: leaving it set would quietly route
            // every later WebView in the app (bots, instant view) through the
            // relay tunnel.
            if (proxyOverrideSet && WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
                ProxyController.getInstance().clearProxyOverride(new java.util.concurrent.Executor() {
                    public void execute(Runnable r) {
                        r.run();
                    }
                }, new Runnable() {
                    public void run() {
                    }
                });
                proxyOverrideSet = false;
            }
        } catch (Throwable ignore) {
        }
        if (proxy != null) {
            proxy.stop();
            proxy = null;
        }
    }

    private void restartApp() {
        // Native reads relay.cfg once, in init(), so settings only take effect
        // in a fresh process.
        //
        // Start Telegram explicitly rather than via getLaunchIntentForPackage():
        // this activity has its own launcher icon, so the package has two
        // LAUNCHER entries and that call becomes ambiguous - it resolves to the
        // system chooser, and in practice came back here. Saving then looked
        // like the setup screen simply reappearing.
        try {
            Intent i = new Intent(this, org.telegram.ui.LaunchActivity.class);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(i);
        } catch (Throwable ignore) {
        }
        Runtime.getRuntime().exit(0);
    }

    // ---- tiny view helpers, so the flow above reads as a flow --------------

    private TextView title(String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextSize(22);
        t.setPadding(0, 0, 0, dp(8));
        root.addView(t);
        return t;
    }

    private TextView body(String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setPadding(0, 0, 0, dp(16));
        root.addView(t);
        return t;
    }

    private TextView note(String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextSize(13);
        t.setTextColor(Color.DKGRAY);
        t.setPadding(0, dp(8), 0, dp(8));
        root.addView(t);
        return t;
    }

    private EditText edit(String hint, int inputType) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setInputType(inputType);
        root.addView(e);
        return e;
    }

    private Button button(String text) {
        Button b = new Button(this);
        b.setText(text);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(12);
        b.setLayoutParams(lp);
        root.addView(b);
        return b;
    }

    private void footer() {
        TextView t = new TextView(this);
        t.setText("device " + DeviceId.shortForm());
        t.setTextSize(11);
        t.setTextColor(Color.GRAY);
        t.setPadding(0, dp(24), 0, 0);
        root.addView(t);
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }
}
