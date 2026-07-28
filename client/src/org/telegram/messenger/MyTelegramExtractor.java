package org.telegram.messenger;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pulls api_id / api_hash off the my.telegram.org pages.
 *
 * The one rule that matters for correctness: <b>scan innerText, never HTML</b>.
 * The login page carries a hidden <code>random_hash</code> field and the
 * create-app form a hidden <code>hash</code>, both 32 hex characters - exactly
 * the shape of an api_hash. Values of hidden inputs never appear in innerText,
 * so reading text instead of markup excludes them structurally rather than by
 * guesswork. The real values render inside visible spans on /apps and are in
 * innerText.
 *
 * Everything here is best-effort: my.telegram.org can change, add a challenge,
 * or refuse. The setup flow always keeps a manual entry path for that reason.
 */
public class MyTelegramExtractor {

    public static final String URL_APPS = "https://my.telegram.org/apps";
    public static final String HOST = "my.telegram.org";

    /** JS evaluated in the page; returns a small JSON blob. */
    public static final String SCRIPT =
            "(function(){" +
            "  if (location.host !== 'my.telegram.org') return '{}';" +
            "  var t = (document.body && document.body.innerText) || '';" +
            "  var id = null, hash = null, m;" +
            "  var els = document.querySelectorAll('label, .form-group, strong, h4, div');" +
            "  for (var i = 0; i < els.length; i++) {" +
            "    var s = els[i].innerText || '';" +
            "    if (!id   && (m = /api_id[^0-9]{0,40}(\\d{5,10})/i.exec(s)))          id = m[1];" +
            "    if (!hash && (m = /api_hash[^0-9a-f]{0,40}([0-9a-f]{32})/i.exec(s)))  hash = m[1];" +
            "  }" +
            "  if (!hash && (m = /\\b([0-9a-f]{32})\\b/.exec(t))) hash = m[1];" +
            "  if (!id   && (m = /api_id[\\s\\S]{0,80}?\\b(\\d{5,10})\\b/i.exec(t))) id = m[1];" +
            "  return JSON.stringify({id: id, hash: hash, path: location.pathname});" +
            "})()";

    /** Prefill the create-app form, but never submit it: the user presses the
     *  button, so we are not creating something on their account unasked. */
    public static final String SCRIPT_PREFILL =
            "(function(){" +
            "  var t = document.querySelector('input[name=app_title]');" +
            "  var s = document.querySelector('input[name=app_shortname]');" +
            "  if (t && !t.value) t.value = 'Messenger';" +
            "  if (s && !s.value) s.value = 'msgr' + Math.floor(Math.random()*100000);" +
            "  var r = document.querySelector('input[name=app_platform][value=android]');" +
            "  if (r) r.checked = true;" +
            "  return 'ok';" +
            "})()";

    public static class Result {
        public int apiId;
        public String apiHash = "";

        public boolean complete() {
            return apiId != 0 && apiHash.length() == 32;
        }
    }

    private static final Pattern P_ID = Pattern.compile("\"id\"\\s*:\\s*\"?(\\d{5,10})\"?");
    private static final Pattern P_HASH = Pattern.compile("\"hash\"\\s*:\\s*\"([0-9a-f]{32})\"");
    private static final Pattern P_PATH = Pattern.compile("\"path\"\\s*:\\s*\"([^\"]*)\"");

    /**
     * Parse what the script returned. The value arrives from evaluateJavascript
     * as a JSON *string literal*, so it is double-encoded; rather than unescape
     * it we just match the inner fields, which is enough for three flat values.
     */
    public static Result parse(String jsResult) {
        Result r = new Result();
        if (jsResult == null) {
            return r;
        }
        String s = jsResult.replace("\\\"", "\"").replace("\\\\", "\\");
        Matcher mp = P_PATH.matcher(s);
        if (mp.find() && !mp.group(1).startsWith("/apps")) {
            // Only /apps shows the real credentials. Anywhere else, anything
            // that looks like a hash is something else.
            return r;
        }
        Matcher mh = P_HASH.matcher(s);
        if (mh.find()) {
            r.apiHash = mh.group(1);
        }
        Matcher mi = P_ID.matcher(s);
        if (mi.find()) {
            try {
                r.apiId = Integer.parseInt(mi.group(1));
            } catch (NumberFormatException ignore) {
            }
        }
        return r;
    }
}
