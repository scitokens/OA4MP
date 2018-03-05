package org.scitokens.util;

import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/26/17 at  3:20 PM
 */
public interface STConstants extends OA2Constants {
    public  static String IETF_CAPUT = "urn:ietf:params:";
    public static final String TOKEN_EXCHANGE_GRANT_TYPE = IETF_CAPUT + "grant_type:token_exchange";
    public static final String ACCESS_TOKEN_TYPE = IETF_CAPUT + "token_type:access_token";
    public static final String REFRESH_TOKEN_TYPE = IETF_CAPUT + "token_type:refresh_token";
    public static final String SUBJECT_TOKEN= "subject_token";
    public static final String SUBJECT_TOKEN_TYPE= "subject_token_type";

}