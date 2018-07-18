package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.GroupElement;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.Groups;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ATServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2DiscoveryServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2SQLTStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.IssuerTransactionState;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.server.ATIResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.configuration.TemplateUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.scitokens.loader.STSE;
import org.scitokens.util.*;
import org.scitokens.util.claims.STFunctorFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;
import static org.scitokens.util.PermissionResolver.ST_GROUP_NAME;
import static org.scitokens.util.PermissionResolver.ST_USER_NAME;
import static org.scitokens.util.SciTokensClaims.ST_CLIENT_IDENTIFIER;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  1:10 PM
 */
public class STATServlet extends OA2ATServlet implements STConstants {
    @Override
    protected IssuerTransactionState doAT(HttpServletRequest request, HttpServletResponse response, OA2Client client) throws Throwable {
        IssuerTransactionState state = super.doAT(request, response, client);
        ATIResponse2 atResponse = (ATIResponse2) state.getIssuerResponse();
        if (((STSE) getServiceEnvironment()).isATasSTEnabled()) {
            ServletDebugUtil.dbg(this, "Minting new SciToken for " + atResponse.getAccessToken());
            // reset token to SciToken here.
            String newAT = getRawSciToken((STTransaction) state.getTransaction(),
                    atResponse.getAccessToken(),
                    atResponse.getParameters(),
                    ((STSE) getServiceEnvironment()).getJsonWebKeys().getDefault());
            AccessTokenImpl ati = new AccessTokenImpl(URI.create(newAT), null);
            atResponse.setAccessToken(ati);
        }
        return state;
    }

    @Override
    protected boolean executeByGrant(String grantType, HttpServletRequest request, HttpServletResponse response) throws Throwable {
        if (!grantType.equals(TOKEN_EXCHANGE_GRANT_TYPE)) {
            return super.executeByGrant(grantType, request, response);
        }
        String subjectToken = getFirstParameterValue(request, SUBJECT_TOKEN);
        if (subjectToken == null) {
            throw new GeneralException("Error: missing subject token");
        }
        AccessToken accessToken = null;
        RefreshToken refreshToken = null;
        JSONObject sciTokens = null;
        STTransaction t = null;
        OA2TokenForge tokenForge = ((OA2TokenForge) getServiceEnvironment().getTokenForge());
        JSONWebKeys keys = ((STSE) getServiceEnvironment()).getJsonWebKeys();
        String subjectTokenType = getFirstParameterValue(request, SUBJECT_TOKEN_TYPE);
        if (subjectTokenType == null || subjectTokenType.isEmpty()) {
            throw new GeneralException("Error: missing subject token type");
        }
        if (subjectTokenType.equals(ACCESS_TOKEN_TYPE)) {
            // So we have an access token. Try to interpret it first as a standard OA4MP access token:
            try {
                sciTokens = SciTokensUtil.verifyAndReadJWT(subjectToken, keys);
                accessToken = tokenForge.getAccessToken(sciTokens.getString(org.scitokens.util.SciTokensClaims.JWT_ID));

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
                if(zzz instanceof OA2SQLTStore){
                    t = (STTransaction) ((OA2SQLTStore)zzz).getByRefreshToken(refreshToken);

                }else {
                    t = (STTransaction) zzz.get(refreshToken.getToken());
                }
            } catch (Throwable tt) {
                throw new GeneralException("Error: Could not get a refresh token:" + tt.getMessage());
            }
        }


        if (t == null) {
            throw new GeneralException("Error: no pending transaction found.");
        }
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put(OA2Claims.ISSUER, OA2DiscoveryServlet.getIssuer(request));
        parameters.put(OA2Claims.SUBJECT, t.getUsername());
        // mint a new access token for this.
        accessToken = tokenForge.getAccessToken();
        t.setAccessToken(accessToken);
        String rawSciToken = getRawSciToken(t, accessToken, parameters, keys.getDefault());
        JSONObject claims = new JSONObject();

        claims.put(OA2Constants.ACCESS_TOKEN, rawSciToken);
        OA2Client oa2Client = (OA2Client) t.getClient();
        // only return a refresh token if the server is configured to do so and the client is too.
        if (oa2Client.isRTLifetimeEnabled() && ((STSE) getServiceEnvironment()).isRefreshTokenEnabled()) {
            refreshToken = tokenForge.getRefreshToken();
            t.setRefreshToken(refreshToken);

            claims.put(OA2Constants.REFRESH_TOKEN, refreshToken.getToken());
        }
        claims.put("issued_token_type", STConstants.ACCESS_TOKEN_TYPE);
        claims.put(OA2Constants.TOKEN_TYPE, "Bearer");
        claims.put(OA2Constants.EXPIRES_IN, Long.toString(Long.valueOf(System.currentTimeMillis() / 1000L + 900L)));
        t.setClaims(claims); // now stash it for future use.
        getTransactionStore().save(t);
        PrintWriter osw = response.getWriter();
        claims.write(osw);
        osw.flush();
        osw.close();
        return true;

    }


    String rawTemplates = "[\n" +
               "{\"read\": \"file:///home/${" + ST_GROUP_NAME + "}/${" + ST_USER_NAME + "}/**\"},\n" +
               "{\"write\": \"file:///home/${" + ST_GROUP_NAME + "}/${" + ST_USER_NAME + "}/**\"},\n" +
               "{\"execute\":\"file:///home/${" + ST_GROUP_NAME + "}/${" + ST_USER_NAME + "}/**\"},\n" +
               "{\"execute\":\"file:///c:/users/${" + ST_USER_NAME + "}/aesir/**\"},\n" +
               "{\"read\": \"ftp://data.bigstate.edu/secure/${"+ST_GROUP_NAME + "}/**\"},\n" +
               "{\"write\": \"ftp://data.bigstate.edu/secure/${"  + ST_GROUP_NAME + "}/${" + ST_USER_NAME + "}/**\"}\n" +
               "  ]\n";
       JSONArray templates = null;
       /*
       TESTS TO DO
       test .../*foo.xls for permissions to specific files.
       scitokens:/scopes?write#ftp://data.bigstate.edu/home/asgaard/project29/data

        */


       protected JSONArray getTemplates() {
           if (templates == null) {
               templates = JSONArray.fromObject(rawTemplates);
               System.out.println("**templates\n" + templates);
           }
           return templates;
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

        JSONObject sciTokens = stTransaction.getClaims();
        // Make the default set of claims
        sciTokens.put(org.scitokens.util.SciTokensClaims.JWT_ID, accessToken.getToken());

        sciTokens.put(ISSUER, parameters.get(ISSUER));
        sciTokens.put(SUBJECT, parameters.get(SUBJECT));
        sciTokens.put(EXPIRATION, Long.valueOf(System.currentTimeMillis() / 1000L + 900L));
        sciTokens.put(AUDIENCE, parameters.get("client_id"));
        sciTokens.put(ST_CLIENT_IDENTIFIER, parameters.get("client_id"));
        sciTokens.put(ISSUED_AT, Long.valueOf(System.currentTimeMillis() / 1000L));
        sciTokens.put(NOT_VALID_BEFORE, Long.valueOf((System.currentTimeMillis()-5000L) / 1000L)); // not before is 5 minutes before current

        STClient stClient = (STClient) stTransaction.getClient();
        // process them.
        if(!stClient.getSciTokensConfig().isEmpty()) {
            STClaimsProcessor claimsProcessor = new STClaimsProcessor(stClient.getSciTokensConfig());

            STFunctorFactory functorFactory = new STFunctorFactory(sciTokens, claimsProcessor);
            claimsProcessor.process(sciTokens);
        }
        Groups groups = new Groups();
                  groups.put(new GroupElement("area51"));
                  groups.put(new GroupElement("asgaard"));
                  groups.put(new GroupElement("aesir"));

        //PermissionResolver permissionResolver = new PermissionResolver(claimsHandler.getTemplates(),
        // Next we make replacements as needed in the templates for claims. These are used for resolution.
        JSONArray replacedTemplates = new JSONArray();
        for(int i = 0; i < getTemplates().size(); i++){
            replacedTemplates.add(TemplateUtil.replaceAll(getTemplates().get(i).toString(), sciTokens));
        }
        PermissionResolver permissionResolver = new PermissionResolver(replacedTemplates,
                sciTokens.getString(SUBJECT),groups );
        DebugUtil.dbg(this, "ST scopes = " + stTransaction.getStScopes());
        DebugUtil.dbg(this, "scopes = " + stTransaction.getScopes());
        if(stTransaction.getScopes()!=null) {
            JSONArray scopeArray = new JSONArray();
            for(String token : stTransaction.getScopes()){
                try{
                    URI s = permissionResolver.resolve(URI.create(token));
                    DebugUtil.dbg(this, "** resolved scope=" + s);

                     if(s != null){
                         scopeArray.add(s.toString()); // or the JSONArray object serializes it into a huge object.
                     }
                }catch(Throwable t){
                    warn("Invalid URI \"" + token + "\" is ignored");
                }
            }
            String scopeString = "";
            boolean firstPass = true;
            for(int i = 0; i < scopeArray.size(); i++){
                scopeString = scopeString + (firstPass?"":" ") + scopeArray.getString(i).trim();
                if(firstPass ){
                    firstPass = false;
                }
            }
            sciTokens.put(org.scitokens.util.SciTokensClaims.ST_SCOPE, scopeString);
        }

        DebugUtil.dbg(this, "scitoken=" + sciTokens.toString(2));
        stTransaction.setClaims(sciTokens);
        String newAT = SciTokensUtil.createJWT(sciTokens, key);

        return newAT;
    }
}
