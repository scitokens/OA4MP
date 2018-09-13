package org.scitokens.util.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2FunctorFactory;
import edu.uiuc.ncsa.security.util.functor.JFunctor;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.scitokens.util.STClaimsProcessor;

import java.util.Collection;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/18 at  7:39 AM
 */
public class STFunctorFactory extends OA2FunctorFactory {
    public STFunctorFactory(Map<String, Object> claims,
                            Collection<String> scopes,
                            STClaimsProcessor handler) {
        super(claims, scopes);
        this.handler = handler;
    }

    STClaimsProcessor handler;

    @Override
    protected JFunctor figureOutFunctor(JSONObject rawJson) {
        JFunctor ff = null;
        if (hasEnum(rawJson, STFunctorClaimTypes.ACCESS)) {
            jAccess j = new jAccess(claims);
            j.setTemplates(rawJson.getJSONArray(STFunctorClaimTypes.ACCESS.getValue()));
            rawJson.put(STFunctorClaimTypes.ACCESS.getValue(), new JSONArray());
            if (handler != null) {
                handler.getAccessList().add(j);
            }
            ff = j;
            return ff;
        }
        return  super.figureOutFunctor(rawJson);

    }


}
