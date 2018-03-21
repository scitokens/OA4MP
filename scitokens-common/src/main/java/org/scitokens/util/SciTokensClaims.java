package org.scitokens.util;

import edu.uiuc.ncsa.security.oauth_2_0.server.OA2Claims;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/22/18 at  4:06 PM
 */
public interface SciTokensClaims extends OA2Claims {
    public static final String JWT_ID = "jti";
    public static String ST_SCOPE = "scp";
    public static String ST_CLIENT_IDENTIFIER = "cid";

}
