package org.scitokens.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATServer2;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.scitokens.util.SciTokensUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;

/**
 * A very, very simple (as in stupid) ready servlet. This is the target of the callback uri supplied in
 * the initial request. <br><br>This example is intended to show control flow rather than be a polished application.
 * Feel free to boilerplate from it as needed. Do not deploy this in production environments.
 * <p>Created by Jeff Gaynor<br>
 * <p/>
 * on 2/10/12 at  1:43 PM
 */

public class STReadyServlet extends ClientServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        if (request.getParameterMap().containsKey(OA2Constants.ERROR)) {
            throw new OA2RedirectableError(request.getParameter(OA2Constants.ERROR),
                    request.getParameter(OA2Constants.ERROR_DESCRIPTION),
                    request.getParameter(OA2Constants.STATE));
        }
        // Get the cert itself. The server itself does a redirect using the callback to this servlet
        // (so it is the portal that actually is invoking this method after the authorization
        // step.) The token and verifier are peeled off and used
        // to complete the request.
        info("2.a. Getting token and verifier.");
        String token = request.getParameter(CONST(ClientEnvironment.TOKEN));
        String state = request.getParameter(OA2Constants.STATE);
        if (token == null) {
            warn("2.a. The token is " + (token == null ? "null" : token) + ".");
            GeneralException ge = new GeneralException("Error: This servlet requires parameters for the token and possibly verifier.");
            request.setAttribute("exception", ge);
            JSPUtil.fwd(request, response, getCE().getErrorPagePath());
            return;
        }
        info("2.a Token found.");

        AuthorizationGrant grant = new AuthorizationGrantImpl(URI.create(token));
        info("2.a. Getting the cert(s) from the service");
        String identifier = clearCookie(request, response);
        OA2Asset asset = null;
        if (identifier == null) {
            asset = (OA2Asset) getCE().getAssetStore().getByToken(BasicIdentifier.newID(token));
            if (asset != null) {
                identifier = asset.getIdentifierString();
            }
        }
        AssetResponse assetResponse = null;
        OA2MPService oa2MPService = (OA2MPService) getOA4MPService();

        ATResponse2 atResponse2 = null;

        //UserInfo ui = null;
        boolean getCerts = ((OA2ClientEnvironment) getCE()).getScopes().contains(OA2Scopes.SCOPE_MYPROXY);
        if (identifier == null) {
            // Since this is a demo servlet, we don't blow up if there is no identifier found, just can't save anything.
            String msg = "Error: no cookie found. Cannot save certificates";
            warn(msg);
            debug("No cookie found");
            atResponse2 = oa2MPService.getAccessToken(asset, grant);
        } else {
            asset = (OA2Asset) getCE().getAssetStore().get(identifier);
            if (asset.getState() == null || !asset.getState().equals(state)) {
                // Just a note: This is most likely to arise when the server's authorize-init.jsp has been
                // changed or replaced and the hidden field for the state (passed to the form, then passed back
                // and therefore not stored on the server anyplace) is missing.
                warn("The expected state from the server was \"" + asset.getState() + "\", but instead \"" + state + "\" was returned. Transaction aborted.");
                throw new IllegalArgumentException("Error: The state returned by the server is invalid.");
            }
            atResponse2 = oa2MPService.getAccessToken(asset, grant);
        }

        info("2.b. Done! Displaying success page.");
        String rawAT = atResponse2.getAccessToken().getToken();
        if (rawAT == null || rawAT.length() == 0) {
            throw new NFWException("Error: no access token returned.");
        }

        OA2ClientEnvironment oa2ce = (OA2ClientEnvironment) getEnvironment();
        ATServer2 atServer2 = (ATServer2) oa2ce.getDelegationService().getAtServer();
        JSONWebKeys jsonWebKeys = atServer2.getJsonWebKeys();

        boolean isVerified = false;
        boolean isSciToken = false;
        try {
            JSONObject scitoken = SciTokensUtil.verifyAndReadJWT(rawAT, jsonWebKeys);
            request.setAttribute("st_payload", scitoken.toString(2));
            isVerified = true;
            isSciToken = true;
        } catch (Throwable t) {
            request.setAttribute("st_payload", rawAT );
            isSciToken = false;
        }
        // we bit of formatting...
        if(isSciToken) {
            int width = 80;
            String formattedToken = "";
            for (int i = 0; i < rawAT.length() / width; i++) {
                formattedToken = formattedToken + rawAT.substring(i * width, (i + 1) * width) + "\n";
            }
            if (0 != rawAT.length() % width) {
                // if there is anything left over, append it, otherwise, skip this.
                formattedToken = formattedToken + rawAT.substring(rawAT.length() - rawAT.length() % width);
            }

            request.setAttribute("accessToken", formattedToken);
            String[] atParts = SciTokensUtil.decat(rawAT);
            String h = atParts[SciTokensUtil.HEADER_INDEX];
            JSONObject header = null;

            String p = atParts[SciTokensUtil.PAYLOAD_INDEX];
            try {
                header = JSONObject.fromObject(new String(Base64.decodeBase64(h)));
                request.setAttribute("st_accessToken2", atResponse2.getAccessToken().getToken());
                request.setAttribute("st_accessToken", formattedToken);
                request.setAttribute("st_header", header.toString(2));
                request.setAttribute("st_verified", Boolean.toString(isVerified));
                JSONWebKey webKey = jsonWebKeys.get(header.get(JWTUtil.KEY_ID));
                String keyPEM = KeyUtil.toX509PEM(webKey.publicKey);
                request.setAttribute("st_public_key", keyPEM);

            } catch (Throwable t) {
                getMyLogger().warn("Error decoding header from response", t);
                System.err.println("Returned raw AT=" + rawAT);
            }
        }else{
            // The server is not configured to return a SciToken at the first step, so just print this out.
                 request.setAttribute("st_accessToken2", rawAT);
                 request.setAttribute("st_accessToken", rawAT);
                 request.setAttribute("st_header", "(none)");
                 request.setAttribute("st_verified", "(n/a)");
                 request.setAttribute("st_public_key", "(n/a)");
        }


        // now we need to get the JWK that was used and return it in PEM format.

        String contextPath = request.getContextPath();
        if (!contextPath.endsWith("/")) {
            contextPath = contextPath + "/";
        }
        request.setAttribute("action", contextPath);
        info("2.a. Completely finished with delegation.");
        JSPUtil.fwd(request, response, getCE().getSuccessPagePath());
        return;
    }

}