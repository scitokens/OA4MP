package org.scitokens.util.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.CAFunctorFactory;
import edu.uiuc.ncsa.security.util.functor.JFunctor;
import edu.uiuc.ncsa.security.util.functor.LogicBlock;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.scitokens.util.STClaimsHandler;

import java.util.List;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/18 at  7:39 AM
 */
public class STFunctorFactory extends CAFunctorFactory {
    public STFunctorFactory(Map<String, Object> claims, STClaimsHandler handler) {
        super(claims);
        this.handler = handler;
    }

    STClaimsHandler handler;

    @Override
    protected JFunctor figureOutFunctor(JSONObject rawJson) {
        JFunctor ff = super.figureOutFunctor(rawJson);
        if (ff != null) {
            // already got one.
            return ff;
        }
        if (hasEnum(rawJson, STFunctorClaimTypes.ACCESS)) {
            jAccess j = new jAccess(claims);
            j.setTemplates(rawJson.getJSONArray(STFunctorClaimTypes.ACCESS.getValue()));
            rawJson.put(STFunctorClaimTypes.ACCESS.getValue(), new JSONArray());
            if (handler != null) {
                handler.getAccessList().add(j);
            }
            ff = j;
        }
        return ff;
    }

    @Override
    public List<LogicBlock> createLogicBlock(JSONArray array) {

        return super.createLogicBlock(array);
    }
}
