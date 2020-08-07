package org.scitokens.util.functor;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.functor.claims.OA2FunctorFactory;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.functor.FunctorTypeImpl;
import edu.uiuc.ncsa.security.util.functor.LogicBlock;
import edu.uiuc.ncsa.security.util.functor.LogicBlocks;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.Collection;
import java.util.Map;

/**
 * After the claims have been created, processing can be applied to them as per configuration.
 * <p>Created by Jeff Gaynor<br>
 * on 3/2/18 at  3:12 PM
 * @deprecated Use {@link OA2ClaimsUtil} instead
 */

public class ClaimsProcessor {
    /**
     * This configuration is part of the client and can be accessed by {@link edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client#getConfig()}
     */
    protected JSONObject config;

    public ClaimsProcessor(JSONObject config) {
        this.config = config;
    }

    protected LogicBlocks<? extends LogicBlock> logicBlocks;

    public Map<String, Object> process(Map<String, Object> claims) {
        ServletDebugUtil.trace(this, "starting processing");

        if(config == null || config.isEmpty()){
            ServletDebugUtil.trace(this, "NO configuration, returning.");
            return claims;
        }

        logicBlocks = createLogicBlocks(config, claims);
        ServletDebugUtil.trace(this, "created " + logicBlocks.size() + " logic blocks.");
        logicBlocks.execute();
        executed = true;
        ServletDebugUtil.trace(this, "Finished processing, returned claims are");
        ServletDebugUtil.trace(this, claims.toString());

        return claims;
    }

    public boolean isExecuted() {
        return executed;
    }

    protected OA2FunctorFactory createFunctorFactory(Map<String, Object> claims, Collection<String> scopes){
        return new OA2FunctorFactory(claims, scopes);
    }
    /**
     * create the logic blocks for this configuration. It also configures the factory
     * @param configuration
     * @return
     */
    protected LogicBlocks<? extends LogicBlock> createLogicBlocks(JSONObject configuration,
                                                                  Map<String, Object> claims){
        ServletDebugUtil.trace(this, "config:\n\n" + config.toString(2));
        OA2FunctorFactory functorFactory = createFunctorFactory(claims, null);

        JSONArray jsonArray = new JSONArray();
        jsonArray.add(config);
        JSONObject j = new JSONObject();
        j.put(FunctorTypeImpl.OR.getValue(), jsonArray);
        ServletDebugUtil.trace(this, "created logic blocks:\n\n" + j.toString(2));

        return functorFactory.createLogicBlock(j);

    }
    protected boolean executed = false;
}
