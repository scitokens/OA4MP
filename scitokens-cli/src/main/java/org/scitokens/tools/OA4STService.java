package org.scitokens.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RefreshTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATServer2;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;
import org.scitokens.util.TokenExchangeConstants;
import org.scitokens.util.SciTokensUtil;

import java.net.URI;
import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/11/17 at  11:41 AM
 */
public class OA4STService extends OA2MPService {
    public OA4STService(ClientEnvironment environment) {
        super(environment);
    }

    public JSONObject exchangeRefreshToken(OA2Asset asset, RefreshToken refreshToken) {
        ServiceClient serviceClient = getServiceClient();

        // Since this is new, we have to roll our own from scratch.
        HashMap<String, String> parameterMap = new HashMap<>();
        parameterMap.put(OA2Constants.GRANT_TYPE, TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        parameterMap.put("subject_token_type", TokenExchangeConstants.REFRESH_TOKEN_TYPE);
        parameterMap.put("subject_token", refreshToken.getToken());

        String rawResponse = serviceClient.getRawResponse(parameterMap);

        System.out.println("raw response = " + rawResponse);
        JSONObject json = JSONObject.fromObject(rawResponse);
        updateAsset(asset, json);
        JSONWebKeys keys = SciTokensUtil.getJsonWebKeys(serviceClient, ((OA2ClientEnvironment) getEnvironment()).getWellKnownURI());

        return SciTokensUtil.verifyAndReadJWT(json.getString(OA2Constants.ACCESS_TOKEN), keys);

    }
    protected void updateAsset(OA2Asset asset, JSONObject claims){
        String rt = claims.getString(OA2Constants.REFRESH_TOKEN);
        if(rt != null && !rt.isEmpty()){
            RefreshToken refreshToken = new OA2RefreshTokenImpl(URI.create(rt));
            asset.setRefreshToken(refreshToken);
        }
        // reset access token to returned value and stash it
        String at = claims.getString(OA2Constants.ACCESS_TOKEN);
        AccessTokenImpl accessToken = new AccessTokenImpl(URI.create(at));
       asset.setAccessToken(accessToken);
       getEnvironment().getAssetStore().save(asset);
    }
    public JSONObject exchangeAccessToken(OA2Asset asset, AccessToken accessToken) {
        ServiceClient serviceClient = getServiceClient();

        // Since this is new, we have to roll our own from scratch.
        HashMap<String, String> parameterMap = new HashMap<>();
        parameterMap.put(OA2Constants.GRANT_TYPE, TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        parameterMap.put("subject_token_type", TokenExchangeConstants.ACCESS_TOKEN_TYPE);
        parameterMap.put("subject_token", accessToken.getToken());

        String rawResponse = serviceClient.getRawResponse(parameterMap);

        System.out.println("raw response = " + rawResponse);
        JSONObject json = JSONObject.fromObject(rawResponse);
        updateAsset(asset, json);
        JSONWebKeys keys = SciTokensUtil.getJsonWebKeys(serviceClient, ((OA2ClientEnvironment) getEnvironment()).getWellKnownURI());

        return SciTokensUtil.verifyAndReadJWT(json.getString(OA2Constants.ACCESS_TOKEN), keys);
    }

    public ServiceClient getServiceClient() {
        ATServer2 atServer2 = (ATServer2) getEnvironment().getDelegationService().getAtServer();
        return atServer2.getServiceClient();
    }
}
