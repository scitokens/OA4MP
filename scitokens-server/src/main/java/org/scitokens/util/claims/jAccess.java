package org.scitokens.util.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.ClaimFunctor;
import net.sf.json.JSONArray;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/18 at  7:39 AM
 */
public class jAccess extends ClaimFunctor {
    public jAccess( Map<String, Object> claims) {
        super(STFunctorClaimTypes.ACCESS, claims);
    }

    @Override
    public Object execute() {
       // This is really a no-op functor. All that is needed is the argument list for later.
        result = null;
        executed = true;
        return result;
    }

    public void setTemplates(JSONArray templates) {
        this.templates = templates;
    }

    public JSONArray getTemplates() {
        return templates;
    }

    JSONArray templates = new JSONArray();
}
