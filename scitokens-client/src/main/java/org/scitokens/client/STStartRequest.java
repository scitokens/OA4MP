package org.scitokens.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreUtil;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import org.scitokens.util.TokenExchangeConstants;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

/**
 * A simple servlet that starts the request. It will make the initial request and set an identifier
 * cookie in the users browser. If there is an {@link edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore} configured, it will make
 * an entry for the {@link edu.uiuc.ncsa.myproxy.oa4mp.client.Asset} resulting from this delegation.
 * <br><br>
 * This example is intended to show control flow rather than be a polished application.
 * Feel free to boilerplate from it as needed. Do not deploy this in production environments.
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/12 at  10:24 AM
 */
public class STStartRequest extends ClientServlet {
    public static final String SCOPE_CAPUT = "demo:";
    // as per https://tools.ietf.org/html/draft-ietf-oauth-resource-indicators-00
    //public static final String RESOURCE_KEY = "resource:";

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        info("1.a. Starting transaction");

        OA4MPResponse gtwResp = null;
        // Drumroll please: here is the work for this call.
        Identifier id = AssetStoreUtil.createID();
        OA2ClientEnvironment oa2ce = (OA2ClientEnvironment) getEnvironment();
        Collection<String> oldScopes = oa2ce.getScopes();
        // Block to snarf up scopes and add them.
        // We are ignoring the old scopes which are by default openid and such.
        // We only want new scopes.
        System.err.println(getClass().getSimpleName() + ": scopes in CE= " + oa2ce.getScopes());

        String rawScopes = request.getParameter("scopes");
        System.err.println(getClass().getSimpleName() + ": scopes = " + rawScopes);
        List<String> newScopes = null;
        if (rawScopes != null) {
            newScopes = new ArrayList<>();
//            newScopes.addAll(oldScopes);
            StringTokenizer st = new StringTokenizer(rawScopes, " ");
            while (st.hasMoreTokens()) {
                String x = st.nextToken();
                newScopes.add(x.trim());
            }
        }
        System.err.println(getClass().getSimpleName() + ": setting scopes to " + newScopes);
        oa2ce.setScopes(newScopes);
        String rawAudience = request.getParameter(TokenExchangeConstants.RESOURCE);
        HashMap<String,String> map = new HashMap<>();
        map.put(TokenExchangeConstants.RESOURCE, rawAudience);



        gtwResp = getOA4MPService().requestCert(id, map);

        // if there is a store, store something in it.
        Cookie cookie = new Cookie(OA4MP_CLIENT_REQUEST_ID, id.getUri().toString());
        cookie.setMaxAge(15 * 60); // 15 minutes
        cookie.setSecure(true);
        debug("id = " + id.getUri());
        response.addCookie(cookie);
        info("1.b. Got response. Creating page with redirect for " + gtwResp.getRedirect().getHost());
        if (getCE().isShowRedirectPage()) {
            request.setAttribute(REDIR, REDIR);
            request.setAttribute("redirectUrl", gtwResp.getRedirect().toString());
            request.setAttribute(ACTION_KEY, ACTION_KEY);
            request.setAttribute("action", ACTION_REDIRECT_VALUE);

            // Normally, we'd just do a redirect, but we will put up a page and show the redirect to the user.
            // The client response contains the generated private key as well
            // In a real application, the private key would be stored. This, however, exceeds the scope of this
            // sample application -- all we need to do to complete the process is send along the redirect url.

            info("1.b. Showing redirect page.");
            JSPUtil.fwd(request, response, getCE().getRedirectPagePath());
            return;
        }
        response.sendRedirect(gtwResp.getRedirect().toString());
    }

}