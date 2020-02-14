package org.scitokens.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.Groups;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.util.configuration.TemplateUtil;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/8/18 at  8:55 AM
 */
public class PermissionResolver {
    String username = null;
    Groups group = null;
    JSONArray templates = null;


    public static final String ST_PATH = "scopes";
    public static final String ST_SCHEME = "scitokens";
    public static final String ST_READ = "read";
    public static final String ST_WRITE = "write";
    public static final String ST_EXECUTE = "execute";
    public static final String ST_QUEUE = "queue";
    public static final String ST_GROUP_NAME = "group";
    public static final String ST_USER_NAME = "sub";

    protected boolean hasUsername() {
        return username != null;
    }

    protected boolean hasGroups() {
        return group != null && !group.isEmpty();
    }

    protected URI processNew(URI request) {
        DebugUtil.trace(this, "processNew: validating request");

        validate(request);
        DebugUtil.trace(this, "processNew: request valid");

        String query = request.getQuery();
        URI fragment = URI.create(request.getFragment());
        String permission = request.getQuery();
        DebugUtil.trace(this, "processNew: template size = " + templates.size());

        for (int i = 0; i < templates.size(); i++) {
            JSONObject json = templates.getJSONObject(i);
            DebugUtil.trace(this, "processNew: permission = " + permission);
            DebugUtil.trace(this, "processNew: template  = " + json);

            if (json.containsKey(permission)) {

                String tempP = json.getString(permission);
                DebugUtil.trace(this, "processNew: tempP start with? " + fragment.getScheme());
                if (tempP.startsWith(fragment.getScheme() + ":")) {
                    URI out = check(tempP, fragment);
                    if (out != null) {
                        return createResponseURI(request);
                    }
                }
            }else{
                DebugUtil.trace(this, "processNew: permission NOT FOUND");

            }
        }
        return null;

    }


    /**
     * Resolves the request based on the permission templates. This return either a URI if there was a successful
     * resolution or a null if there was not.
     *
     * @param request
     * @return
     */
    public URI resolve(URI request) {
        // old otken = what is used currently in SciTokens and is of the form e.g. read:path
        // This is converted to a standard new request with an implicit request for file:///path
        // so that our permission machinery works on it.
        DebugUtil.trace(this, " resolve: originial request=\"" + request + "\"");
        if (isOldToken(request)) {
            request = URI.create(ST_SCHEME + ":/" + ST_PATH + "?" + request.getScheme() + "#file://" + request.getPath());
            DebugUtil.trace(this, " resolve: converted to \"" + request + "\"");
        }
        return processNew(request);
    }

    protected URI createResponseURI(URI request) {
        // you need the original request, not the fragment!!!
        return URI.create(request.getQuery() + ":" + URI.create(request.getFragment()).getPath()); // you need the original request, not the fragment!!!
    }

    protected URI check(String template, URI resource) {
        DebugUtil.trace(this,"testing " + resource + " against template " + template);
        ArrayList<String> tests = new ArrayList<>();
        boolean un = template.contains("${" + ST_USER_NAME + "}");
        if (template.contains("${" + ST_GROUP_NAME + "}")) {
            // do replacements
            if (!hasGroups()) {
                throw new IllegalStateException("Error: group requested, but no groups for this user were found");
            }
            for (String key : group.keySet()) {
                HashMap<String, String> group = new HashMap<>();
                group.put(ST_GROUP_NAME, key);
                if (hasUsername() && un) {
                    group.put(ST_USER_NAME, username);
                }
                String replacedString = TemplateUtil.replaceAll(template, group);
                DebugUtil.trace(this, template + " --> " + replacedString);
                tests.add(replacedString);
            }


        } else {
            if (un) {
                // replace username but there are no groups.
                HashMap<String, String> group = new HashMap<>();
                group.put(ST_USER_NAME, username);
                tests.add(TemplateUtil.replaceAll(template, group));

            }
            // no groups, single
        }
        for (String template1 : tests) {
            DebugUtil.trace(this, "   testing: " + template1);
            if (template1.endsWith("/**")) {
                // implies sub paths, not substrings, so /foo/** implies /foo, /foo/ and /foo/baz are ok,
                // but /foobar is not
                String noStars = null;
                String r = resource.toString();
                if (!r.endsWith("/")) {
                    // normalize it a bit
                    r = r + "/";
                }
                noStars = template1.substring(0, template1.length() - 2); // keep trailing slash
                if (r.startsWith(noStars)) {
                    DebugUtil.trace(this, "   testing: returning " + resource);
                    return resource;
                }
            } else {
                if (template1.equals(resource.toString())) {
                    DebugUtil.trace(this, "   testing: returning " + resource);
                    return resource;
                }
            }
        }
        System.err.println("   testing: returning NULL");

        return null;
    }

    public PermissionResolver(JSONArray templates, String username, Groups group) {
        this.username = username;
        this.templates = templates;
        this.group = group;
    }

    public PermissionResolver(JSONArray templates) {
        this.templates = templates;
        if (templates == null || templates.isEmpty()) {
            throw new IllegalArgumentException("Error: null templates encountered.");
        }
    }

    protected boolean isOldToken(URI request) {
        return request.getScheme().equals(ST_READ) || request.getScheme().equals(ST_WRITE)
                || request.getScheme().equals(ST_EXECUTE) || request.getScheme().equals(ST_QUEUE);


    }

    /**
     * This checks that the scheme is valid, that the path is correct for this operation and
     * that the requested action is recognized.
     *
     * @param uri
     */

    protected void validate(URI uri) {
        boolean firstCheck = uri.getScheme().equals(ST_SCHEME) && uri.getPath().equals("/" + ST_PATH);
        if (!firstCheck) {
            throw new IllegalArgumentException("Error: Invalid URI for request");
        }
        String query = uri.getQuery();
        if (!(query.equals(ST_READ) || query.equals(ST_WRITE) || query.equals(ST_EXECUTE) || query.equals(ST_QUEUE))) {
            throw new IllegalArgumentException("Error: Invalid URI for request");
        }
    }
}
