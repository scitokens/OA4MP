package org.scitokens.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.security.core.Identifier;
import net.sf.json.JSONObject;
import org.scitokens.util.claims.AuthorizationTemplates;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/7/18 at  4:59 PM
 */
public class STClient extends OA2Client {
    public static final String SCITOKENS_KEY = "sciTokens";
    public STClient(Identifier identifier) {
        super(identifier);
    }

    public JSONObject getSciTokensConfig(){
        if(config == null || config.isEmpty() || !config.containsKey(SCITOKENS_KEY)){
            return new JSONObject();
        }
        return config.getJSONObject(SCITOKENS_KEY);
    }

    public AuthorizationTemplates getAuthorizationTemplates() {
        if(authorizationTemplates == null){
            authorizationTemplates  = STClientConfigurationUtil.getAuthorizationTemplates(getConfig());
        }
        return authorizationTemplates;
    }

    protected AuthorizationTemplates authorizationTemplates;

}
