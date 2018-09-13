package org.scitokens.util;

import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/26/17 at  3:20 PM
 */
public interface TokenExchangeConstants extends OA2Constants {
    public  static String IETF_CAPUT = "urn:ietf:params:"; // Should never change.
    public static final String TOKEN_EXCHANGE_GRANT_TYPE = IETF_CAPUT + "grant_type:token_exchange";
    public static final String ACCESS_TOKEN_TYPE = IETF_CAPUT + "token_type:access_token";
    public static final String REFRESH_TOKEN_TYPE = IETF_CAPUT + "token_type:refresh_token";
    public static final String ID_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:id_token";
    //Indicates that the token is a base64url-encoded SAML 1.1
    public static final String SAML1_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:saml1";
    //Indicates that the token is a base64url-encoded SAML 2.0
    public static final String SAML2_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:saml2";
    // This is tricky since it means that the requested type is specifically a JWT
    public static final String JWT_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:jwt";
    public static final String ISSUED_TOKEN_TYPE = "issued_token_type";
    public static final String ACTOR_TOKEN= "actor_token";
    public static final String ACTOR_TOKEN_TYPE= "actor_token_type";
    public static final String SUBJECT_TOKEN= "subject_token";
    public static final String SUBJECT_TOKEN_TYPE= "subject_token_type";
    public static final String AUDIENCE = "audience";
    public static final String RESOURCE = "resource";
    public static final String TOKEN_TYPE_BEARER = "Bearer"; //as per RFC 6750
    public static final String TOKEN_TYPE_MAC = "MAC"; //as per RFC 6750

}
