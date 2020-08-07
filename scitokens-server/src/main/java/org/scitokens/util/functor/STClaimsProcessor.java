package org.scitokens.util.functor;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.functor.claims.OA2FunctorFactory;
import edu.uiuc.ncsa.security.util.functor.LogicBlock;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/18 at  7:30 AM
 */
public class STClaimsProcessor extends ClaimsProcessor {
    public STClaimsProcessor(JSONObject config) {
        super(config);
    }

    public ArrayList<jAccess> getAccessList() {
        return accessList;
    }

    ArrayList<jAccess> accessList = new ArrayList<>();

    @Override
    public Map<String, Object> process(Map<String, Object> claims) {
        logicBlocks = createLogicBlocks(config, claims);
        for (LogicBlock logicBlock : logicBlocks) {
            logicBlock.execute();
        }
        executed = true;
        return claims;
    }

    public JSONArray getTemplates() {
        JSONArray templates = new JSONArray();
        if (isExecuted()) {
            for (jAccess jj : getAccessList()) {
                if (jj.isExecuted()) {
                    templates.addAll(jj.getTemplates());
                }
            }
        }
        return templates;
    }

    @Override
    protected OA2FunctorFactory createFunctorFactory(Map<String, Object> claims, Collection<String> scopes) {
        return new STFunctorFactory(claims, scopes, this);
    }
}
