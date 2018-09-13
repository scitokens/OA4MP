package org.scitokens.util.claims;

import edu.uiuc.ncsa.security.core.util.BeanUtils;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.Collection;
import java.util.LinkedList;

/**
 * Each entry is keyed to an audience and this is how permissions are found. An audience may be any string and may
 * include templates.
 * <p>Created by Jeff Gaynor<br>
 * on 8/2/18 at  2:41 PM
 */
public class AuthorizationTemplate {
    public AuthorizationTemplate(JSONObject json) {
        fromJSON(json);
    }

    public AuthorizationTemplate(String audience,
                                 Collection<AuthorizationPath> paths) {
        this.audience = audience;
        this.paths = paths;
    }

    String audience;
    Collection<AuthorizationPath> paths;

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }


    public Collection<AuthorizationPath> getPaths() {
        return paths;
    }

    public void setPaths(Collection<AuthorizationPath> paths) {
        this.paths = paths;
    }

    public JSONObject toJSON() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(OA2Claims.AUDIENCE, audience);
        JSONArray array = new JSONArray();
        for (AuthorizationPath path : paths) {
            array.add(path.toJSON());
        }
        jsonObject.put("paths", array);
        return jsonObject;
    }

    public void fromJSON(JSONObject jsonObject) {
        audience = jsonObject.getString(OA2Claims.AUDIENCE);
        JSONArray x = jsonObject.getJSONArray("paths");
        paths = new LinkedList<>();
        for (int i = 0; i < x.size(); i++) {
            AuthorizationPath authorizationPath = new AuthorizationPath(x.getJSONObject(i));
            paths.add(authorizationPath);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if(!(obj instanceof AuthorizationTemplate))return false;
        AuthorizationTemplate at = (AuthorizationTemplate)obj;
        if(!BeanUtils.checkEquals(at.audience, audience)) return false;
        if(at.getPaths().size() != getPaths().size()) return false;
        for(AuthorizationPath ap: getPaths()){
            if(!at.getPaths().contains(ap)) return false;
        }
        return true;
    }
}
