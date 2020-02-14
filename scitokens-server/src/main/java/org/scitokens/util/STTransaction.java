package org.scitokens.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import net.sf.json.JSONObject;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  8:26 AM
 */
public class STTransaction extends OA2ServiceTransaction {
    public STTransaction(AuthorizationGrant ag) {
        super(ag);
    }

    public STTransaction(Identifier identifier) {
        super(identifier);
    }

    JSONObject claims;

    /**
     * These are the claims that are returned as the SciToken. Note that these are used to build the JWT
     * that contains a signature, but we only store the actual claims.
     * @return
     */
    @Override
    public JSONObject getClaims() {
        if(claims == null){
            claims = new JSONObject();
        }
        return claims;
    }

    public void setClaims(JSONObject claims) {
        this.claims = claims;
    }

    public String getStScopes() {
        return stScopes;
    }

    public void setStScopes(String stScopes) {
        this.stScopes = stScopes;
    }

    String stScopes;

    public List<String> getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    List<String> audience;

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * KLUDGE. We are introducing versions to ScoTokens and need to start putting in the machinery. Initially
     * all this does is allow us to write version 2 code and ignore it. This should be configurable somehow. The
     * question then is if this is set per client or if it is part of the request per transaction. At the least, having it
     * in the transaction is not wrong for the granularity...
     */
    String version = STClientConfigurationUtil.VERSION_1_0;


}
