package org.scitokens.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CLCCommands;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;
import org.scitokens.util.SciTokensUtil;

/**
 * These are commands for the tester. These talk to the service token endpoint and will issue requests for
 * tokens and such.
 * <p>Created by Jeff Gaynor<br>
 * on 12/11/17 at  10:31 AM
 */
public class STClientCommands extends OA2CLCCommands {
    public STClientCommands(MyLoggingFacade logger, ClientEnvironment ce) {
        super(logger, ce);
    }

    @Override
     public OA2MPService getService() {
         if (service == null) {
             service = new OA4STService(getCe());
         }
         return service;
     }
    protected void exchangeHelp(){
        sayi("exchange [-at|-rt]");
        sayi("This will exchange the current access token (so you need to have gotten that far first)");
        sayi("for a secure token. The response will contain other information that will be displayed.");
        sayi("If there is no parameter, the current access token is used for the exchange");
        sayi("Otherwise you may specify -at to exchange the access token or -rt to exchange using the refresh token.");
    }

    JSONObject sciToken = null;
    public void exchange(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            exchangeHelp();
            return;
        }
        boolean didIt = false;
        if(1 == inputLine.size() || inputLine.hasArg("-at")) {
            didIt = true;
            AccessToken at = getDummyAsset().getAccessToken();

            OA4STService stService = (OA4STService) getService();

            JSONObject response = stService.exchangeAccessToken(getDummyAsset(), at);
            sciToken = response;
            sayi(response.toString(2));
        }
        if(inputLine.hasArg("-rt")) {
            didIt = true;
            RefreshToken rt = getDummyAsset().getRefreshToken();

            OA4STService stService = (OA4STService) getService();

            JSONObject response = stService.exchangeRefreshToken(getDummyAsset(), rt);
            sciToken = response;

            sayi(response.toString(2));

        }
        if(!didIt){
            sayi("Sorry, argument not understood");
            exchangeHelp();

        }


    }

    protected void showSciTokenHelp(){
        sayi("showscitoken = This will show the last SciToken from the token exchange endpoint.");

    }
    public void showscitoken(InputLine inputLine) throws Exception{
        if (showHelp(inputLine)) {
            showSciTokenHelp();
            return;
        }

        if(sciToken == null){
            sayi("no sci token");
            return;
        }
        sayi(sciToken.toString(2));
    }


    @Override
    public void getat(InputLine inputLine) throws Exception {
        super.getat(inputLine);
        AccessToken accessToken = getDummyAsset().getAccessToken();
        OA4STService stService = (OA4STService) getService();
        JSONWebKeys keys = SciTokensUtil.getJsonWebKeys(stService.getServiceClient(), ((OA2ClientEnvironment) getService().getEnvironment()).getWellKnownURI());

        try {
            JSONObject json=JWTUtil.verifyAndReadJWT(accessToken.getToken(), keys);
            sayi("Access token is a JWT:");
            say(json.toString(2));
        }catch(Throwable t){
            // do nothing.
        }
    }
}
