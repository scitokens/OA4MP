package org.scitokens.util;

import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/22/18 at  4:06 PM
 */
public interface SciTokensClaims extends OA2Claims {
    public static final String JWT_ID = "jti";
    public static String ST_SCOPE = "scope";
    public static String ST_CLIENT_IDENTIFIER = "cid";
    public static String CLAIM_OPERATION_WRITE = "write";
    public static String CLAIM_OPERATION_READ = "read";
    public static String CLAIM_OPERATION_QUEUE = "queue";
    public static String CLAIM_OPERATION_EXECUTE = "execute";

}
