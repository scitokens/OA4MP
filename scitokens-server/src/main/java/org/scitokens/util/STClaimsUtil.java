package org.scitokens.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;

import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.ISSUED_AT;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.NOT_VALID_BEFORE;
import static org.scitokens.util.SciTokensClaims.ST_CLIENT_IDENTIFIER;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/1/18 at  3:54 PM
 */
public class STClaimsUtil extends OA2ClaimsUtil {
    public STClaimsUtil(OA2SE oa2se, STTransaction transaction) {
        super(oa2se, transaction);
    }

    protected STTransaction getSTT(){
        return (STTransaction) transaction;
    }

    /**
     * Here is where the claims for the ST token are fist created.
     * @param request
     * @param p
     * @return
     */
    @Override
    public JSONObject initializeClaims(HttpServletRequest request, JSONObject p) {
        JSONObject sciTokens = new JSONObject();
        JSONObject parameters = getSTT().getClaims();
          // Make the default set of claims
          sciTokens.put(org.scitokens.util.SciTokensClaims.JWT_ID, getSTT().getAccessToken().getToken());
          STClient stClient = (STClient) transaction.getClient();
          sciTokens.put(ISSUER, parameters.get(ISSUER));
          sciTokens.put(SUBJECT, parameters.get(SUBJECT));
          sciTokens.put(EXPIRATION, Long.valueOf(System.currentTimeMillis() / 1000L + 900L));
          sciTokens.put(AUDIENCE, stClient.getIdentifierString());
          sciTokens.put(ST_CLIENT_IDENTIFIER, stClient.getIdentifierString());
          sciTokens.put(ISSUED_AT, Long.valueOf(System.currentTimeMillis() / 1000L));
          sciTokens.put(NOT_VALID_BEFORE, Long.valueOf((System.currentTimeMillis()-5000L) / 1000L)); // not before is 5 minutes before current

        return sciTokens;
    }
}
