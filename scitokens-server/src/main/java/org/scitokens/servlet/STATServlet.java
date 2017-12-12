package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ATServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2DiscoveryServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.IssuerTransactionState;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.server.ATIResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.server.OA2Claims;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;
import org.scitokens.util.STConstants;
import org.scitokens.util.STTransaction;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.security.oauth_2_0.server.OA2Claims.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  1:10 PM
 */
public class STATServlet extends OA2ATServlet {
    @Override
    protected IssuerTransactionState doAT(HttpServletRequest request, HttpServletResponse response, OA2Client client) throws Throwable {
        IssuerTransactionState state = super.doAT(request, response, client);
        ATIResponse2 atResponse = (ATIResponse2) state.getIssuerResponse();
        // reset token to SciToken here.
        String newAT = getRawSciToken((STTransaction) state.getTransaction(),
                atResponse.getAccessToken(),
                atResponse.getParameters(),
                ((OA2SE) getServiceEnvironment()).getJsonWebKeys().getDefault());
        AccessTokenImpl ati = new AccessTokenImpl(URI.create(newAT), null);
        atResponse.setAccessToken(ati);
        return state;
    }

    @Override
    protected boolean executeByGrant(String grantType, HttpServletRequest request, HttpServletResponse response) throws Throwable {
        if (!grantType.equals(STConstants.TOKEN_EXCHANGE_GRANT_TYPE)) {
            return super.executeByGrant(grantType, request, response);
        }
        String subjectToken = getFirstParameterValue(request, "subject_token");
        if (subjectToken == null) {
            throw new GeneralException("Error: missing access token");
        }
        AccessToken accessToken = null;
        JSONObject sciTokens = null;
        JSONWebKeys keys = ((OA2SE) getServiceEnvironment()).getJsonWebKeys();
        // So we have an access token. Try to interpret it first as a standard OA4MP access token:
        try {
            sciTokens = JWTUtil.verifyAndReadJWT(subjectToken, keys);
            accessToken = getServiceEnvironment().getTokenForge().getAccessToken(sciTokens.getString(STConstants.JWT_ID));

        } catch (Throwable t) {
            // didn't work, so now we assume it is a SciToken and verify then parse it
            accessToken = getServiceEnvironment().getTokenForge().getAccessToken(subjectToken);
        }

        STTransaction t = (STTransaction) getTransactionStore().get(accessToken);
        if (t == null) {
            throw new GeneralException("Error: no pending transaction found.");
        }
        HashMap<String,String> parameters = new HashMap<>();
        parameters.put(OA2Claims.ISSUER,OA2DiscoveryServlet.getIssuer(request));
        parameters.put(OA2Claims.SUBJECT,t.getUsername());
        String rawSciToken = getRawSciToken(t, accessToken,parameters, keys.getDefault());
       JSONObject claims = new JSONObject();
        claims.put(OA2Constants.ACCESS_TOKEN, rawSciToken);
        claims.put("issued_token_type", STConstants.SUBJECT_TOKEN_TYPE);
        claims.put(OA2Constants.TOKEN_TYPE, "Bearer");
        claims.put(OA2Constants.EXPIRES_IN, Long.toString(Long.valueOf(System.currentTimeMillis() / 1000L + 900L)));

        PrintWriter osw = response.getWriter();
        claims.write(osw);
        osw.flush();
        osw.close();
        return true;

    }

    /**
     * This creates a SciToken
     *
     * @param stTransaction
     * @param accessToken
     * @param parameters
     * @param key
     * @return
     */
    public String getRawSciToken(STTransaction stTransaction,
                                 AccessToken accessToken,
                                 Map<String, String> parameters,
                                 JSONWebKey key
    ) throws Throwable {
        JSONObject sciTokens = new JSONObject();
        sciTokens.put(STConstants.JWT_ID, accessToken.getToken());

        //Map<String, String> parameters = atResponse.getParameters();
        //STTransaction stTransaction = ;

        sciTokens.put(ISSUER, parameters.get(ISSUER));
        sciTokens.put(SUBJECT, parameters.get(SUBJECT));
        sciTokens.put(EXPIRATION, Long.valueOf(System.currentTimeMillis() / 1000L + 900L));
        //  sciTokens.put(AUDIENCE, parameters.get("client_id"));
        sciTokens.put(ISSUED_AT, Long.valueOf(System.currentTimeMillis() / 1000L));
/*
        JSONArray array = new JSONArray();
        array.add("read:/protected");
        array.add("write:protected");
        sciTokens.put("authz", array);
*/
        sciTokens.put("path", "/user/" + stTransaction.getUsername());
        sciTokens.put(STConstants.ST_SCOPE, "read:/protected");
        DebugUtil.dbg(STATServlet.class, "scitoken=" + sciTokens.toString(2));
        String newAT = JWTUtil.createJWT(sciTokens, key);

        return newAT;
    }
}
