package org.scitokens.util;

import edu.uiuc.ncsa.security.oauth_2_0.server.config.ClientConfigurationUtil;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.scitokens.util.claims.AuthorizationTemplates;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/3/18 at  8:43 AM
 */
public class STClientConfigurationUtil extends ClientConfigurationUtil {
    public static String SCI_TOKENS_KEY = "scitokens";
    public static String AUTHORIZATION_TEMPLATES_KEY = "templates";

    /**
     * Return a component in the SciTokens configuration.
     * <pre>
     *     Z = {"sciTokens":
     *      {"key0":X}
     *      }
     * </pre>
     * getSTThingy(Z,"key0") returns X
     *
     * @param config
     * @param key
     * @return
     */
    protected static JSONArray getSTThingy(JSONObject config, String key) {
        return getThingies(SCI_TOKENS_KEY, config, key);
    }

    public static AuthorizationTemplates getAuthorizationTemplates(JSONObject config) {
        JSONArray object = getSTThingy(config, AUTHORIZATION_TEMPLATES_KEY);
        AuthorizationTemplates at = new AuthorizationTemplates();
        at.fromJSON(object);
        return at;
    }

    public static void setAuthorizationTemplates(JSONObject config, AuthorizationTemplates authorizationTemplates) {
        setThingy(SCI_TOKENS_KEY, config, AUTHORIZATION_TEMPLATES_KEY, authorizationTemplates.toJSON());

    }
}
