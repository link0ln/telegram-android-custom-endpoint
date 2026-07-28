package org.telegram.messenger;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Setup screen. Nothing is baked into the binary: the user supplies their own
 * api_id / api_hash and the relay endpoint, plus a setup code when the relay
 * runs a subscription.
 */
public class ConfigActivity extends Activity {

    private EditText codeEdit, apiIdEdit, apiHashEdit, endpointEdit;
    private Button saveBtn;
    private TextView statusView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        int pad = dp(20);
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);
        scroll.addView(root);

        TextView title = new TextView(this);
        title.setText("Setup");
        title.setTextSize(22);
        title.setPadding(0, 0, 0, dp(6));
        root.addView(title);

        TextView hint = new TextView(this);
        hint.setText("Paste the setup code you were given. If you are running your own relay, "
                + "leave it empty and enter the endpoint host below instead.\n\n"
                + "api_id and api_hash come from your own account at my.telegram.org.");
        hint.setPadding(0, 0, 0, dp(16));
        root.addView(hint);

        codeEdit = new EditText(this);
        codeEdit.setHint("setup code (host|TOKEN|CHECK)");
        codeEdit.setInputType(InputType.TYPE_CLASS_TEXT);
        root.addView(codeEdit);

        endpointEdit = new EditText(this);
        endpointEdit.setHint("endpoint host (e.g. relay.example.com)");
        endpointEdit.setInputType(InputType.TYPE_CLASS_TEXT);
        root.addView(endpointEdit);

        apiIdEdit = new EditText(this);
        apiIdEdit.setHint("api_id (number)");
        apiIdEdit.setInputType(InputType.TYPE_CLASS_NUMBER);
        root.addView(apiIdEdit);

        apiHashEdit = new EditText(this);
        apiHashEdit.setHint("api_hash");
        apiHashEdit.setInputType(InputType.TYPE_CLASS_TEXT);
        root.addView(apiHashEdit);

        if (CustomConfig.getApiId() != 0) {
            apiIdEdit.setText(String.valueOf(CustomConfig.getApiId()));
        }
        apiHashEdit.setText(CustomConfig.getApiHash());
        endpointEdit.setText(CustomConfig.getEndpoint());

        saveBtn = new Button(this);
        saveBtn.setText("Save & connect");
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        blp.topMargin = dp(20);
        saveBtn.setLayoutParams(blp);
        root.addView(saveBtn);

        statusView = new TextView(this);
        statusView.setPadding(0, dp(12), 0, 0);
        root.addView(statusView);

        TextView device = new TextView(this);
        device.setText("device id: " + DeviceId.shortForm());
        device.setPadding(0, dp(20), 0, 0);
        device.setTextSize(12);
        root.addView(device);

        setContentView(scroll);

        saveBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                onSave();
            }
        });
    }

    private void onSave() {
        final String codeText = codeEdit.getText().toString().trim();
        final String hash = apiHashEdit.getText().toString().trim();
        String epTyped = endpointEdit.getText().toString().trim();
        String tokenTyped = "";
        String ipPinned = null;

        if (!codeText.isEmpty()) {
            RelayClient.SetupCode sc = RelayClient.parseSetupCode(codeText);
            if (sc == null) {
                toast("That setup code doesn't look right - check for a missing character.");
                return;
            }
            epTyped = sc.host;
            tokenTyped = sc.token;
            ipPinned = sc.ip;
        }

        int id = 0;
        try {
            id = Integer.parseInt(apiIdEdit.getText().toString().trim());
        } catch (Exception ignore) {
        }
        if (id == 0 || hash.isEmpty() || epTyped.isEmpty()) {
            toast("Enter a setup code (or endpoint host), plus api_id and api_hash.");
            return;
        }

        final int apiId = id;
        final String ep = epTyped;
        final String token = tokenTyped;
        final String pinnedIp = ipPinned;
        saveBtn.setEnabled(false);
        saveBtn.setText("Checking " + ep + " ...");

        new Thread(new Runnable() {
            public void run() {
                final String ip = pinnedIp != null && !pinnedIp.isEmpty()
                        ? pinnedIp : CustomConfig.resolve(ep);
                if (ip == null) {
                    fail("Can't look up " + ep + " on this network.");
                    return;
                }
                if (token.isEmpty()) {
                    // self-hosted relay: nothing to validate
                    finish(apiId, hash, ep, ip, "", "");
                    return;
                }
                RelayClient.Status st = RelayClient.ping(ep, ip, token, 12000);
                if (st.code == RelayClient.ST_OK) {
                    finish(apiId, hash, ep, ip, token, st.pin);
                    return;
                }
                fail(describe(st));
            }
        }).start();
    }

    /**
     * Turn a status into something honest.
     *
     * ST_NO_ANSWER deliberately does not say "wrong code": the relay masks an
     * unknown token to its cover site, so a bad code and a blocked network are
     * indistinguishable on the wire. Claiming to know which one happened would
     * be a lie, and a confident wrong answer sends people down the wrong path.
     */
    private String describe(RelayClient.Status st) {
        switch (st.code) {
            case RelayClient.ST_EXPIRED:
                return "This subscription has expired. Renew it, then try again.";
            case RelayClient.ST_DEVICE_LIMIT:
                return "This code is already in use on the maximum number of devices "
                        + "(this device is " + DeviceId.shortForm() + ").";
            case RelayClient.ST_SUSPENDED:
                return "This subscription is not active.";
            case RelayClient.ST_QUOTA:
                return "This subscription is over its traffic quota.";
            case RelayClient.ST_BUSY:
                return "The relay is busy. Try again in a minute.";
            default:
                return "Couldn't set up with this code on this network. "
                        + "Check the code, or try mobile data instead of Wi-Fi.";
        }
    }

    private void finish(final int apiId, final String hash, final String ep,
                        final String ip, final String token, final String pin) {
        runOnUiThread(new Runnable() {
            public void run() {
                CustomConfig.saveEndpoint(ep, ip, token, pin);
                CustomConfig.saveApiCredentials(apiId, hash);
                restartApp();
            }
        });
    }

    private void fail(final String message) {
        runOnUiThread(new Runnable() {
            public void run() {
                saveBtn.setEnabled(true);
                saveBtn.setText("Save & connect");
                statusView.setText(message);
            }
        });
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
    }

    private void restartApp() {
        // Native reads relay.cfg once, during init(), so a config change only
        // takes effect on a fresh process.
        try {
            Intent i = getPackageManager().getLaunchIntentForPackage(getPackageName());
            if (i != null) {
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                startActivity(i);
            }
        } catch (Throwable ignore) {
        }
        Runtime.getRuntime().exit(0);
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }
}
