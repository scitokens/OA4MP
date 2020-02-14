package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.GroupElement;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.Groups;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ATServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2SQLTStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.IssuerTransactionState;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.server.ATIResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.configuration.TemplateUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;
import org.scitokens.loader.STSE;
import org.scitokens.util.*;
import org.scitokens.util.claims.*;
import org.scitokens.util.functor.STClaimsProcessor;
import org.scitokens.util.functor.STFunctorFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import static edu.uiuc.ncsa.security.core.util.DebugUtil.trace;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.EXPIRATION;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.ISSUED_AT;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.ISSUER;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.IS_MEMBER_OF;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.NOT_VALID_BEFORE;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.SUBJECT;
import static org.scitokens.util.PermissionResolver.ST_GROUP_NAME;
import static org.scitokens.util.PermissionResolver.ST_USER_NAME;
import static org.scitokens.util.SciTokensClaims.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  1:10 PM
 */
public class STATServlet extends OA2ATServlet implements TokenExchangeConstants {
    @Override
    protected IssuerTransactionState doAT(HttpServletRequest request, HttpServletResponse response, OA2Client client) throws Throwable {
        IssuerTransactionState state = super.doAT(request, response, client);
        ATIResponse2 atResponse = (ATIResponse2) state.getIssuerResponse();
        // note that we need the access token even if we will return the sci token, since the access token will be included as the
        // jti (JWT id) inside the sci token.
        state.getTransaction().setAccessToken(atResponse.getAccessToken());
        if (((STSE) getServiceEnvironment()).isATasSTEnabled()) {
            ServletDebugUtil.dbg(this, "Minting new SciToken for " + atResponse.getAccessToken());
            // reset token to SciToken here.
            String newAT = getRawSciToken2((STTransaction) state.getTransaction(),
                    atResponse.getParameters());
            AccessTokenImpl ati = new AccessTokenImpl(URI.create(newAT), null);
            atResponse.setAccessToken(ati);
        }
        return state;
    }

    /*
     */

    /**
     * This adds the token exchange endpoint (TXE).
     * To be clear on this, the OAuth 2,0 authorization code flow is what this is based on. The means that scopes are given
     * in the initial request only. The additional TXE (Token Exchange Endpoint) here allows for a scope parameter that is
     * specific to the issued token. This is what I am using as the starting point for SciTokens. This uses the proposed
     * <a href="https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-14">token exchange</a> spec here and
     * the <a href="https://scitokens.org/technical_docs/Claims">Sci Tokens claims doc</a> (as of 8/4/2018).
     * <p/>
     * <h2>>Req. params</h2
     * <ul>
     * <li>grant_type</li>
     * <li>resource - for Sci Tokens, list of uris</li>
     * <li>audience - for Sci Tokens (reserved) aliases for resources</li>
     * <li>scope - for Sci Tokens only</li>
     * <li>requested_token_type</li>
     * <li>subject_token</li>
     * <li>subject_token_type</li>
     * <li>actor_token</li>
     * <li>actor_token_type</li>
     * </ul>
     * <h2>Responses outside of the Sci Tokens</h2>
     * These are required by the TXE for the response
     * <ul>
     * <li>access_token = this <b>is</b> the Sci Token</li>
     * <li>refresh_token = standard OA4MP refresh token</li>
     * <li>issued_token_type</li>
     * <li>token_type</li>
     * <li>expires_in = identical to the value used the Sci Token to calculate the exp (= current time + expires_in) claim there</li>
     * <li>scope = requested scopes from the initial client request, <b>not the sci Tokens request</b></li>
     * <li></li>
     * </ul>
     * <p/>
     * <h2>The Sci Token's claims</h2>
     * <p>This follows the current claims document (which is not a spec and does not claim to be. It is mostly
     * a snapshot of what they are trying to have in their Python code...)</p>
     * <ul>
     * <li>sub = subject = the subject of this token</li>
     * <li>jti = jwt ID = a unique identifier</li>
     * <li>nbf = not before timestamp</li>
     * <li>exp = expiration timestamp</li>
     * <li>iat = issued at timestamp</li>
     * <li>aud = audience = the address where this will be used.</li>
     * <li>iss = issuer</li>
     * <li>scope = scope = permissions, actually.</li>
     * </ul>
     *
     * @param grantType
     * @param request
     * @param response
     * @return
     * @throws Throwable
     */
    @Override
    protected boolean executeByGrant(String grantType, HttpServletRequest request, HttpServletResponse response) throws Throwable {
        // Note this follows
        // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-03#section-2.1
        if (!grantType.equals(TOKEN_EXCHANGE_GRANT_TYPE)) {
            return super.executeByGrant(grantType, request, response);
        }
        String subjectToken = getFirstParameterValue(request, SUBJECT_TOKEN);
        if (subjectToken == null) {
            throw new GeneralException("Error: missing subject token");
        }

        // And now do the spec stuff for the actor token
        String actorToken = getFirstParameterValue(request, ACTOR_TOKEN);
        String actorTokenType = getFirstParameterValue(request, ACTOR_TOKEN_TYPE);
        // We don't support the actor token, and the spec says that we can ignore it
        // *but* if it is missing and the actor token type is there, reject the request
        if ((actorToken == null && actorTokenType != null)) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "invalid request, no actor token type is allowed", HttpStatus.SC_BAD_REQUEST);
        }

        AccessToken accessToken = null;
        RefreshToken refreshToken = null;
        JSONObject sciTokens = null;
        STTransaction t = null;
        OA2TokenForge tokenForge = ((OA2TokenForge) getServiceEnvironment().getTokenForge());
        JSONWebKeys keys = ((STSE) getServiceEnvironment()).getJsonWebKeys();
        String subjectTokenType = getFirstParameterValue(request, SUBJECT_TOKEN_TYPE);
        if (subjectTokenType == null) {
            throw new GeneralException("Error: missing subject token type");
        }
        if (subjectTokenType.equals(ACCESS_TOKEN_TYPE)) {
            // So we have an access token. Try to interpret it first as a standard OA4MP access token:
            try {
                sciTokens = SciTokensUtil.verifyAndReadJWT(subjectToken, keys);
                accessToken = tokenForge.getAccessToken(sciTokens.getString(JWT_ID));

            } catch (Throwable tt) {
                // didn't work, so now we assume it is a SciToken and verify then parse it
                accessToken = getServiceEnvironment().getTokenForge().getAccessToken(subjectToken);
            }
            t = (STTransaction) getTransactionStore().get(accessToken);

        }

        if (subjectTokenType.equals(REFRESH_TOKEN_TYPE)) {
            // So we have an access token. Try to interpret it first as a standard OA4MP access token:
            try {
                refreshToken = tokenForge.getRefreshToken(subjectToken);
                TransactionStore zzz = getTransactionStore();
                // Hack because Java does not seem to be resolving this correctly for the store.
                if (zzz instanceof OA2SQLTStore) {
                    t = (STTransaction) ((OA2SQLTStore) zzz).getByRefreshToken(refreshToken);

                } else {
                    t = (STTransaction) zzz.get(refreshToken.getToken());
                }
            } catch (Throwable tt) {
                throw new GeneralException("Error: Could not get a refresh token:" + tt.getMessage());
            }
        }


        if (t == null) {
            throw new GeneralException("Error: no pending transaction found.");
        }
        /*
        These can come as multiple space delimited string and as multiple parameters, so it is possible to get
        arrays of arrays of these and they have to be regularlized to a single list for processing.
         */
        Collection<String> audience = convertToList(request, AUDIENCE);
        Collection<String> scopes = convertToList(request, OA2Constants.SCOPE);
        Collection<String> resources = convertToList(request, RESOURCE);


        HashMap<String, String> parameters = new HashMap<>();
        parameters.put(OA2Claims.SUBJECT, t.getUsername());
        parameters.put(JWTUtil.KEY_ID, keys.getDefaultKeyID());

        // mint a new access token for this.
        accessToken = tokenForge.getAccessToken();
        t.setAccessToken(accessToken);
//        String rawSciToken = getRawSciToken(t, parameters, resources, scopes, audience);
        String rawSciToken = getRawSciToken2(t, parameters);

        // Now we set up the claims that are returned with the ID token. These look a lot like the sci token claims,
        // but are different. This makes this server an OIDC server, which ok for now.
       /* OA2ClaimsUtil claimsUtil = new OA2ClaimsUtil((OA2SE) getServiceEnvironment(), t);
        JSONObject claims = claimsUtil.createBasicClaims(request, t);*/
        JSONObject claims = new JSONObject();
        // These are for the token exchange server
        claims.put(OA2Constants.ACCESS_TOKEN, rawSciToken);
        OA2Client oa2Client = (OA2Client) t.getClient();
        // only return a refresh token if the server is configured to do so and the client is too.
        if (oa2Client.isRTLifetimeEnabled() && ((STSE) getServiceEnvironment()).isRefreshTokenEnabled()) {
            refreshToken = tokenForge.getRefreshToken();
            t.setRefreshToken(refreshToken);
            claims.put(OA2Constants.REFRESH_TOKEN, refreshToken.getToken());
        }
        claims.put(ISSUED_TOKEN_TYPE, ACCESS_TOKEN_TYPE); // This is the type of token issued (mostly access tokens). Must be as per TX spec.
        claims.put(OA2Constants.TOKEN_TYPE, TOKEN_TYPE_BEARER); // This is how the issued token can be used, mostly. BY RFC 6750 spec.
        claims.put(OA2Constants.EXPIRES_IN, Long.toString(Long.valueOf(System.currentTimeMillis() / 1000L + 900L)));
//        claims.put(OA2Claims.AUDIENCE, t.getClient().getIdentifierString());

        t.setClaims(claims); // now stash it for future use.
        getTransactionStore().save(t);
        PrintWriter osw = response.getWriter();
        claims.write(osw);
        osw.flush();
        osw.close();
        return true;

    }


    String rawTemplates = "[\n" +
            "{\"read\": \"file:///home/${" + ST_GROUP_NAME + "}/${" + ST_USER_NAME + "}*//**\"},\n" +
            "{\"write\": \"file:///home/${" + ST_GROUP_NAME + "}/${" + ST_USER_NAME + "}*//**\"},\n" +
            "{\"execute\":\"file:///home/${" + ST_GROUP_NAME + "}/${" + ST_USER_NAME + "}*//**\"},\n" +
            "{\"execute\":\"file:///c:/users/${" + ST_USER_NAME + "}/aesir*//**\"},\n" +
            "{\"read\": \"ftp://data.bigstate.edu/secure/${" + ST_GROUP_NAME + "}*//**\"},\n" +
            "{\"write\": \"ftp://data.bigstate.edu/secure/${" + ST_GROUP_NAME + "}/${" + ST_USER_NAME + "}*//**\"}\n" +
            "  ]\n";
    JSONArray templates = null;

    protected JSONArray getTemplates() {
        if (templates == null) {
            templates = JSONArray.fromObject(rawTemplates);
            System.out.println("**templates\n" + templates);
        }
        return templates;
    }

    protected AuthorizationTemplates getTestTemplates() {
        String audience = "https://demo.lsst.org";
        AuthorizationTemplates ats = new AuthorizationTemplates();
        LinkedList<AuthorizationPath> aps = new LinkedList<>();
        AuthorizationPath ap = new AuthorizationPath(CLAIM_OPERATION_READ, "/home/${user}");
        aps.add(ap);
        ap = new AuthorizationPath(CLAIM_OPERATION_WRITE, "/home/${user}");
        aps.add(ap);
        AuthorizationTemplate at = new AuthorizationTemplate(audience, aps);
        ats.put(at);
        System.err.println("Authorization templates:");
        System.err.println(ats.toJSON().toString(2));
        return ats;
    }


    public String getRawSciToken2(STTransaction stTransaction, Map<String, String> parameters) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        AccessToken accessToken = stTransaction.getAccessToken();
        STSE stse = (STSE) getServiceEnvironment();
        STClient stClient = (STClient) stTransaction.getClient();

        JSONWebKeys keys = ((STSE) getServiceEnvironment()).getJsonWebKeys();
        JSONWebKey key = keys.getDefault();
        if (parameters.containsKey(JWTUtil.KEY_ID)) {
            key = keys.get(parameters.get(JWTUtil.KEY_ID));
        }

        JSONObject sciTokens = new JSONObject();
        sciTokens.put(JWT_ID, accessToken.getToken());

        AuthorizationTemplates ats = stClient.getAuthorizationTemplates();
        JSONObject claims = stTransaction.getClaims();
        Groups groups = null;
        if (claims.containsKey(IS_MEMBER_OF)) {
            // The point of this block is that there is an is member of claim, but there may be an issue with it.
            // At least a fair bit of this is written with future proofing in mind, so that if something changes
            // there will be an error generated.
            Object rawGroups = claims.get(IS_MEMBER_OF);
            if (rawGroups instanceof String) {
                groups = new Groups();
                try {
                    JSONArray array = JSONArray.fromObject(rawGroups);
                    groups.fromJSON(array);
                } catch (Throwable t) {
                    DebugUtil.dbg(this, "Attempts to interpret group as JSONArray, but was not in the correct format:\n\"" + rawGroups + "\"");
                    // so no groups.
                }
            }
            if (rawGroups instanceof Groups) {
                groups = (Groups) rawGroups;
            }
            if (rawGroups instanceof JSONArray) {
                groups = new Groups();
                groups.fromJSON((JSONArray) rawGroups);
            }
            if (groups == null) {
                throw new NFWException("Unrecognized group structure for class \"" + rawGroups.getClass().getSimpleName() + " = \"" + rawGroups + "\"");
            }
        } else {
            groups = new Groups(); // so no null pointer exception.
        }
        if (!isEmpty(stse.getIssuer())) {
            sciTokens.put(ISSUER, stse.getIssuer());
        } else {
            sciTokens.put(ISSUER, stse.getServiceAddress());
        }
        sciTokens.put(SUBJECT, claims.get(SUBJECT));
        sciTokens.put(EXPIRATION, Long.valueOf(System.currentTimeMillis() / 1000L + 900L));
        DebugUtil.dbg(this, "SciTokens version = " + stTransaction.getVersion());
        if(stTransaction.getVersion().equals(STClientConfigurationUtil.VERSION_2_0)) {
            sciTokens.put(ST_CLIENT_IDENTIFIER, parameters.get("client_id"));
        }
        sciTokens.put(ISSUED_AT, Long.valueOf(System.currentTimeMillis() / 1000L));
        sciTokens.put(NOT_VALID_BEFORE, Long.valueOf((System.currentTimeMillis() - 5000L) / 1000L)); // not before is 5 minutes before current

        String usernameClaimkey = SUBJECT;
        trace(this, "getting username claim key");
        if (stClient.getUsernameClaimKey() != null) {
            usernameClaimkey = stClient.getUsernameClaimKey();
        }
        trace(this, "Got username claim key=" + usernameClaimkey);
        // Now to resolve audience and scope requests.
        if(!claims.containsKey(usernameClaimkey)){
            String message = "Error: there is no username associated with the claim \"" + usernameClaimkey + "\"";
            ServletDebugUtil.warn(this, message);
            throw new IllegalStateException(message);
        }
        TemplateResolver templateResolver = new TemplateResolver(claims.getString(usernameClaimkey), groups);
        LinkedList<String> requestedPermissions = new LinkedList<>();
        StringTokenizer st = new StringTokenizer(stTransaction.getStScopes(), " ");
        while (st.hasMoreElements()) {
            requestedPermissions.add(st.nextToken());
        }
        HashMap<String, List<String>> permissions = new HashMap<>();
        for (String aud : stTransaction.getAudience()) {
            List<String> tempP = templateResolver.resolve(ats, aud, requestedPermissions);
            if (!tempP.isEmpty()) {
                permissions.put(aud, tempP);
            }
        }
        if (permissions.isEmpty()) {
            throw new OA2GeneralError(OA2Errors.INVALID_SCOPE, "No permissions resulted from this request. ", HttpStatus.SC_BAD_REQUEST);
        }
        // now we have to craft the response.
        String audiences = "";
        String pString = "";
        for (String aud : permissions.keySet()) {
            audiences = audiences + " " + aud;
            for (String p : permissions.get(aud)) {
                pString = pString + " " + p;
            }
        }
        sciTokens.put(OA2Claims.AUDIENCE, audiences.trim());
        sciTokens.put(SCOPE, pString.trim());
        String newAT = SciTokensUtil.createJWT(sciTokens, key);

        return newAT;

    }


    /**
     * This creates a SciToken
     *
     * @param stTransaction
     * @param parameters
     * @return
     */
    public String getRawSciToken(STTransaction stTransaction,
                                 Map<String, String> parameters
    ) throws Throwable {

        AccessToken accessToken = stTransaction.getAccessToken();
        STClient stClient = (STClient) stTransaction.getClient();
        JSONWebKeys keys = ((STSE) getServiceEnvironment()).getJsonWebKeys();
        JSONWebKey key = keys.get(parameters.get(JWTUtil.KEY_ID));

        // it is assumed that the parameters contain

        JSONObject sciTokens = new JSONObject();

        // Make the default set of claims
        sciTokens.put(JWT_ID, accessToken.getToken());

        AuthorizationTemplates ats = stClient.getAuthorizationTemplates();
        /* According to the SCiTokens claims document 8/4/2018, the request for audience is of the form

          aud:STUFF

          We just drop the "aud:" and look that the audience is the one intended,
         */
        String audienceCaput = "aud:";
       /* for (String aud : audience) {
            String audKey = aud.substring(audienceCaput.length());
            if (ats.containsKey(audKey)) {
                sciTokens.put(AUDIENCE, audKey);

                AuthorizationTemplate at = ats.get(audKey);

            }

        }*/
        sciTokens.put(ISSUER, stClient.getIdentifierString());
        sciTokens.put(SUBJECT, parameters.get(SUBJECT));
        sciTokens.put(EXPIRATION, Long.valueOf(System.currentTimeMillis() / 1000L + 900L));
        sciTokens.put(ST_CLIENT_IDENTIFIER, parameters.get("client_id"));
        sciTokens.put(ISSUED_AT, Long.valueOf(System.currentTimeMillis() / 1000L));
        sciTokens.put(NOT_VALID_BEFORE, Long.valueOf((System.currentTimeMillis() - 5000L) / 1000L)); // not before is 5 minutes before current

        // process them.
        if (!stClient.getSciTokensConfig().isEmpty()) {
            STClaimsProcessor claimsProcessor = new STClaimsProcessor(stClient.getSciTokensConfig());

            STFunctorFactory functorFactory = new STFunctorFactory(sciTokens, null, claimsProcessor);
            claimsProcessor.process(sciTokens);
        }
        Groups groups = new Groups();
        groups.put(new GroupElement("area51"));
        groups.put(new GroupElement("asgaard"));
        groups.put(new GroupElement("aesir"));

        //PermissionResolver permissionResolver = new PermissionResolver(claimsHandler.getTemplates(),
        // Next we make replacements as needed in the templates for claims. These are used for resolution.
        JSONArray replacedTemplates = new JSONArray();
        for (int i = 0; i < getTemplates().size(); i++) {
            replacedTemplates.add(TemplateUtil.replaceAll(getTemplates().get(i).toString(), sciTokens));
        }
        PermissionResolver permissionResolver = new PermissionResolver(replacedTemplates,
                sciTokens.getString(SUBJECT), groups);
        DebugUtil.dbg(this, "ST scopes = " + stTransaction.getStScopes());
        DebugUtil.dbg(this, "scopes = " + stTransaction.getScopes());
        if (stTransaction.getScopes() != null) {
            JSONArray scopeArray = new JSONArray();
            for (String token : stTransaction.getScopes()) {
                try {
                    URI s = permissionResolver.resolve(URI.create(token));
                    DebugUtil.dbg(this, "** resolved scope=" + s);

                    if (s != null) {
                        scopeArray.add(s.toString()); // or the JSONArray object serializes it into a huge object.
                    }
                } catch (Throwable t) {
                    warn("Invalid URI \"" + token + "\" is ignored");
                }
            }
            String scopeString = "";
            boolean firstPass = true;
            for (int i = 0; i < scopeArray.size(); i++) {
                scopeString = scopeString + (firstPass ? "" : " ") + scopeArray.getString(i).trim();
                if (firstPass) {
                    firstPass = false;
                }
            }
            sciTokens.put(ST_SCOPE, scopeString);
        }

        DebugUtil.dbg(this, "scitoken=" + sciTokens.toString(2));
        stTransaction.setClaims(sciTokens);
        String newAT = SciTokensUtil.createJWT(sciTokens, key);

        return newAT;
    }

    /**
     * Convert a string or list of strings to a list of them. This is for lists of space delimited values
     * The spec allows for multiple value which in practice can also mean that a client makes the request with
     * multiple parameters, so we have to snoop for those and for space delimited string inside of those.
     *
     * @param req
     * @param parameterName
     * @return
     */
    protected List<String> convertToList(HttpServletRequest req, String parameterName) {
        ArrayList<String> out = new ArrayList<>();
        String[] rawValues = req.getParameterValues(parameterName);
        if (rawValues == null) {
            return out;
        }
        for (String v : rawValues) {
            StringTokenizer st = new StringTokenizer(v);
            while (st.hasMoreTokens()) {
                out.add(st.nextToken());
            }
        }
        return out;
    }
}
