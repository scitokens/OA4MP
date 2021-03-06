package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.UserInfoServlet;
import net.sf.json.JSONObject;
import org.scitokens.loader.STSE;
import org.scitokens.util.SciTokensUtil;

import javax.servlet.http.HttpServletRequest;

import static org.scitokens.util.SciTokensClaims.JWT_ID;


/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  5:21 PM
 */
public class STUserInfoServlet extends UserInfoServlet {

    @Override
    protected String getRawAT(HttpServletRequest request) {
        String rawAT = super.getRawAT(request);
        STSE oa2se = (STSE)getServiceEnvironment();
        // The rub here is that we may have to parse this as a JWT token.
        try{
            JSONObject sciToken = SciTokensUtil.verifyAndReadJWT(rawAT, oa2se.getJsonWebKeys());
            if(sciToken.containsKey(JWT_ID)){
                return sciToken.get(JWT_ID).toString();
            }
        }catch(Throwable t){
            // do nothing. Assume it is a standard access token, not a sci token.
        }
        return rawAT;
    }
}
