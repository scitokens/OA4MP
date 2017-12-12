package org.scitokens.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATServer2;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;
import org.scitokens.util.STConstants;

import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/11/17 at  11:41 AM
 */
public class OA4STService extends OA2MPService {
    public OA4STService(ClientEnvironment environment) {
        super(environment);
    }

    public JSONObject exchangeAccessToken(OA2Asset asset, AccessToken accessToken) {
        ATServer2 atServer2 = (ATServer2) getEnvironment().getDelegationService().getAtServer();

        ServiceClient serviceClient = atServer2.getServiceClient();

        // Since this is new, we have to roll our own from scratch.
        HashMap<String, String> parameterMap = new HashMap<>();
        parameterMap.put(OA2Constants.GRANT_TYPE, STConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        parameterMap.put("subject_token_type", STConstants.SUBJECT_TOKEN_TYPE);
        parameterMap.put("subject_token", accessToken.getToken());

        String rawResponse = serviceClient.getRawResponse(parameterMap);

        System.out.println("raw response = " + rawResponse);
        JSONObject json = JSONObject.fromObject(rawResponse);
        JSONWebKeys keys = JWTUtil.getJsonWebKeys(serviceClient, ((OA2ClientEnvironment) getEnvironment()).getWellKnownURI());

        return JWTUtil.verifyAndReadJWT(json.getString(OA2Constants.ACCESS_TOKEN), keys);
    }
}
