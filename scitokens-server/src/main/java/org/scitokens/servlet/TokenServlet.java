package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.oauth_2_0.server.ATIResponse2;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;
import org.scitokens.util.STConstants;
import org.scitokens.util.STTransaction;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A new Servlet that follows IETF draft token exchange specification. Aim of this is to take an access token
 * and be able to return a security token (in this case a SciToken). The spec assumes that access tokens are
 * <b>not</b> secure -- merely opaque strings. In this service, the access token itself is a SciToken,
 * though that is not a requirement.
 * <p>Created by Jeff Gaynor<br>
 * on 12/8/17 at  3:59 PM
 */
public class TokenServlet extends MyProxyDelegationServlet {
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse issuerResponse) throws IOException {
        return null;
    }


    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        String grantType = getFirstParameterValue(httpServletRequest, "grant_type");
        if(grantType == null){
            throw new GeneralException("Error: No grant type");
        }
        if(!grantType.equals(STConstants.TOKEN_EXCHANGE_GRANT_TYPE)){
            throw new GeneralException("Error: Incorrect grant type");
        }
        String subjectTokenType = getFirstParameterValue(httpServletRequest, "subject_token_type");
        if(subjectTokenType == null || !subjectTokenType.equals(STConstants.SUBJECT_TOKEN_TYPE)){
            throw new GeneralException("Error: incorrect or unsupported subject token type");
        }
        String subjectToken = getFirstParameterValue(httpServletRequest, "subject_token");
        if(subjectToken == null){
            throw new GeneralException("Error: missing access token");
        }
        AccessToken accessToken = null;
        JSONObject sciTokens  = null;
        JSONWebKeys keys = ((OA2SE) getServiceEnvironment()).getJsonWebKeys();
        // So we have an access token. Try to interpret it first as a standard OA4MP access token:
        try{
          accessToken = getServiceEnvironment().getTokenForge().getAccessToken(subjectToken);
        }catch(Throwable t){
            // didn't work, so now we assume it is a SciToken and verify then parse it
             sciTokens = JWTUtil.verifyAndReadJWT(subjectToken, keys);
            accessToken = getServiceEnvironment().getTokenForge().getAccessToken(sciTokens.getString(STConstants.JWT_ID));
        }

        STTransaction t = (STTransaction) getTransactionStore().get(accessToken);
        if(t == null){
            throw new GeneralException("Error: no pending transaction found.");
        }
        // so the transaction exists and the access token works.

        // we create a new SciToken then stuff it into yet another JSON object to send back as per the draft spec.

        JSONObject json = new JSONObject();
    }
}
