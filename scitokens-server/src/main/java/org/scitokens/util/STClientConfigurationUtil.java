package org.scitokens.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientFunctorScriptsUtil;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.scitokens.util.claims.AuthorizationTemplates;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/3/18 at  8:43 AM
 */
public class STClientConfigurationUtil extends OA2ClientFunctorScriptsUtil {
    public static String SCI_TOKENS_KEY = "scitokens";
    public static String AUTHORIZATION_TEMPLATES_KEY = "templates";
    public static String VERSION_1_0 = "1.0";
    public static String VERSION_2_0 = "2.0";
    /**
     * If this is present in the configuration, then the value of this claim is used
     * as the username for resolving against templates. The default is the sub claim
     * but any claim may be used. Note that if you specify an non-existent claim, an
     * exception will be raised, so be sure you have actually set the claim before resolution.
     */
    public static String USERNAME_CLAIM_KEY = "usernameClaimKey";

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

    public static String getUsernameClaimKey(JSONObject config) {
        JSONArray stConfig = getSTThingy(config, USERNAME_CLAIM_KEY);
        // Since the last call always wraps whatever in a JSONArray, this should have a single
        // element that is the value we want
        if (!stConfig.isEmpty()) {
            return stConfig.getString(0);
        }
        return null;
    }
}
