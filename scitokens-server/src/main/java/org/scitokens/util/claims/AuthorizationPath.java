package org.scitokens.util.claims;

import edu.uiuc.ncsa.security.core.util.BeanUtils;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/11/18 at  6:25 PM
 */
public class AuthorizationPath {
    String operation;
    String path;

    public AuthorizationPath(JSONObject json) {
        fromJSON(json);
    }

    public AuthorizationPath(String operation, String path) {
        this.operation = operation;
        this.path = path;
    }

    public JSONObject toJSON() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("operation", operation);
        jsonObject.put("path", path);
        return jsonObject;
    }

    public void fromJSON(JSONObject j) {
        operation = j.getString("operation");
        path = j.getString("path");
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AuthorizationPath)) return false;
        AuthorizationPath ap = (AuthorizationPath) obj;
        if (!BeanUtils.checkEquals(ap.operation, operation)) return false;
        if (!BeanUtils.checkEquals(ap.path, path)) return false;
        return true;
    }
}
