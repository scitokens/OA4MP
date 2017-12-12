package org.scitokens.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2TestCommands;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;

/**
 * These are commands for the tester. These talk to the service token endpoint and will issue requests for
 * tokens and such.
 * <p>Created by Jeff Gaynor<br>
 * on 12/11/17 at  10:31 AM
 */
public class STTokenCommands extends OA2TestCommands{
    public STTokenCommands(MyLoggingFacade logger, ClientEnvironment ce) {
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
        sayi("exchange ");
        sayi("This will exchange the current access token (so you need to have gotten that far first)");
        sayi("for a secure token. The response will contain other information that will be displayed.");
    }
    public void exchange(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            exchangeHelp();
            return;
        }
        AccessToken at = getDummyAsset().getAccessToken();

        OA4STService stService = (OA4STService) getService();

        JSONObject response = stService.exchangeAccessToken(getDummyAsset(), at);
        sayi(response.toString(2));
    }
}
