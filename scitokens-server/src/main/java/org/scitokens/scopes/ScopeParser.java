package org.scitokens.scopes;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/7/18 at  4:07 PM
 */
public class ScopeParser {
    public static final String  ST_SCHEME = "scitokens";
    public static final String  ST_PATH = "scope";

    public boolean validate(URI scope){
        return scope.getScheme().equals(ST_SCHEME) && scope.getPath().equals("/" + ST_PATH);
    }
}
