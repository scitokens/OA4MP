package org.scitokens.util;

import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/22/18 at  4:06 PM
 */
public interface SciTokensClaims extends OA2Claims {
    String ST_SCOPE = "scope";
    String ST_CLIENT_IDENTIFIER = "cid";
    String CLAIM_OPERATION_WRITE = "write";
    String CLAIM_OPERATION_READ = "read";
    String CLAIM_OPERATION_QUEUE = "queue";
    String CLAIM_OPERATION_EXECUTE = "execute";

}
