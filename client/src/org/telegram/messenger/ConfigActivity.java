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

/** First-launch setup: api_id, api_hash and relay endpoint. Nothing is baked in. */
public class ConfigActivity extends Activity {

    private EditText apiIdEdit, apiHashEdit, endpointEdit;
    private Button saveBtn;

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
        hint.setText("Enter api_id and api_hash from my.telegram.org, and the relay endpoint hostname to connect through.");
        hint.setPadding(0, 0, 0, dp(16));
        root.addView(hint);

        apiIdEdit = new EditText(this);
        apiIdEdit.setHint("api_id (number)");
        apiIdEdit.setInputType(InputType.TYPE_CLASS_NUMBER);
        root.addView(apiIdEdit);

        apiHashEdit = new EditText(this);
        apiHashEdit.setHint("api_hash");
        apiHashEdit.setInputType(InputType.TYPE_CLASS_TEXT);
        root.addView(apiHashEdit);

        endpointEdit = new EditText(this);
        endpointEdit.setHint("endpoint host (e.g. relay.example.com)");
        endpointEdit.setInputType(InputType.TYPE_CLASS_TEXT);
        root.addView(endpointEdit);

        if (CustomConfig.getApiId() != 0) apiIdEdit.setText(String.valueOf(CustomConfig.getApiId()));
        apiHashEdit.setText(CustomConfig.getApiHash());
        endpointEdit.setText(CustomConfig.getEndpoint());

        saveBtn = new Button(this);
        saveBtn.setText("Save & connect");
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        blp.topMargin = dp(20);
        saveBtn.setLayoutParams(blp);
        root.addView(saveBtn);

        setContentView(scroll);

        saveBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { onSave(); }
        });
    }

    private void onSave() {
        final String ep = endpointEdit.getText().toString().trim();
        final String hash = apiHashEdit.getText().toString().trim();
        int id = 0;
        try { id = Integer.parseInt(apiIdEdit.getText().toString().trim()); } catch (Exception ignore) {}
        if (id == 0 || hash.isEmpty() || ep.isEmpty()) {
            Toast.makeText(this, "Fill all three fields", Toast.LENGTH_SHORT).show();
            return;
        }
        final int apiId = id;
        saveBtn.setEnabled(false);
        saveBtn.setText("Resolving " + ep + " ...");
        new Thread(new Runnable() {
            public void run() {
                final String ip = CustomConfig.resolve(ep);
                runOnUiThread(new Runnable() {
                    public void run() {
                        if (ip == null) {
                            saveBtn.setEnabled(true);
                            saveBtn.setText("Save & connect");
                            Toast.makeText(ConfigActivity.this, "Can't resolve " + ep, Toast.LENGTH_LONG).show();
                            return;
                        }
                        CustomConfig.save(apiId, hash, ep, ip);
                        restartApp();
                    }
                });
            }
        }).start();
    }

    private void restartApp() {
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
