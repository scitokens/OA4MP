package org.scitokens.test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.scopeHandlers.GroupElement;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.scopeHandlers.Groups;
import edu.uiuc.ncsa.security.util.TestBase;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.junit.Test;
import org.scitokens.util.PermissionResolver;
import org.scitokens.util.STClaimsHandler;
import org.scitokens.util.claims.STFunctorClaimTypes;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.scitokens.util.PermissionResolver.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/8/18 at  8:55 AM
 */
public class PermissionParserTest extends TestBase {
    String rawTemplates = "[\n" +
            "    {\"read\": \"file:///home/${" + ST_GROUP_NAME + "}/${" + ST_USER_NAME + "}/**\"},\n" +
            "    {\"read\": \"file://a.b.c/home/area51/${"+ST_GROUP_NAME + "}/**\"},\n" +
            "    {\"write\": \"ftp://a.b.c/area51/${"  + ST_GROUP_NAME + "}/**\"},\n" +
            "    {\"write\": \"file://a.b.c/area51/${" + ST_GROUP_NAME + ")/**\"},\n" +
            "    {\"write\": \"file://a.b.c/area51/${" + ST_GROUP_NAME + "}/${" + ST_USER_NAME + "}\"}\n" +
            "  ]\n";
    JSONArray templates = null;
    /*
    TESTS TO DO
    test .../*foo.xls for permissions to specific files.
    template = /foo/** should fail on /foobar, pass on /foo/, /foo/bar, /foo/bar/
     */

    String rawTemplates2 = "[\n" +
               "    {\"read\": \"file:///home/${" + ST_GROUP_NAME + "}/${" + ST_USER_NAME + "}/**\"},\n" +
              "    {\"write\": \"file:///home/${" + ST_GROUP_NAME + ")/${" + ST_USER_NAME + "}/**\"},\n" +
            "    {\"read\": \"ftp://data.bigstate.edu/home/${"+ST_GROUP_NAME + "}/**\"},\n" +
            "    {\"write\": \"ftp://data.bigstate.edu/${"  + ST_GROUP_NAME + "}/${" + ST_USER_NAME + "}/**\"}\n" +
               "  ]\n";

    protected JSONArray getTemplates() {
        if (templates == null) {
            templates = JSONArray.fromObject(rawTemplates);
        }
        return templates;
    }

    Map<String, Object> claims;

    String TEST_USER_NAME = "thor";
    protected Map<String, Object> getClaims() {
        if (claims == null) {
            claims = new HashMap<>();
            claims.put(ST_USER_NAME, TEST_USER_NAME);
            Groups groups = new Groups();
            groups.put(new GroupElement("test-group1"));
            groups.put(new GroupElement("test-group2"));
            groups.put(new GroupElement("asgaard"));
            claims.put("isMemberOf", groups);
        }
        return claims;
    }

    protected URI createRequest(String action, URI resource) {
        URI request = URI.create(
                ST_SCHEME + ":" +
                "/" + ST_PATH +
                "?" + action +
                "#" + resource);
                return request;
    }

    @Test
    public void testBasic() throws Exception {
        JSONArray templates = JSONArray.fromObject(rawTemplates2);
        System.out.println(templates);

        URI request = createRequest(ST_READ, URI.create("file://a.b.c/home/area51/test-group1"));
        PermissionResolver pr = new PermissionResolver(getTemplates(),TEST_USER_NAME, (Groups)getClaims().get("isMemberOf"));
        assert pr.resolve(request) != null;
    }

    /**
     * template ends in a ** so test that this can have sub-directories
     * @throws Exception
     */
    @Test
    public void testBasic2() throws Exception {
        URI request = createRequest(ST_READ, URI.create("file://a.b.c/home/area51/test-group2/foo/thor"));
        PermissionResolver pr = new PermissionResolver(getTemplates(), TEST_USER_NAME, (Groups)getClaims().get("isMemberOf"));
        assert pr.resolve(request) != null;
    }

    /**
     * Test for a group that does not exist for this user
     * @throws Exception
     */
    @Test
    public void testGroupFail() throws Exception {
        URI request = createRequest(ST_READ, URI.create("file://a.b.c/home/area51/bad-group"));
        PermissionResolver pr = new PermissionResolver(getTemplates(), TEST_USER_NAME, (Groups)getClaims().get("isMemberOf"));
        assert pr.resolve(request) == null;
    }

    @Test
    public void testBadHost() throws Exception {
        URI request = createRequest(ST_READ, URI.create("file://server.evil.org/home/asgaard/thor"));
        PermissionResolver pr = new PermissionResolver(getTemplates(), TEST_USER_NAME, (Groups)getClaims().get("isMemberOf"));
        assert pr.resolve(request) == null;
    }

    @Test
      public void testOldRequest() throws Exception {
          URI request = URI.create(ST_READ +  ":/home/asgaard/thor");
          PermissionResolver pr = new PermissionResolver(getTemplates(), TEST_USER_NAME, (Groups)getClaims().get("isMemberOf"));
          assert pr.resolve(request) != null;
      }
    protected PermissionResolver getPR(){
        return  new PermissionResolver(getTemplates(), TEST_USER_NAME, (Groups)getClaims().get("isMemberOf"));

    }
    /**
     * Check that template that end with ** don't allow more than they should.
     * @throws Exception
     */
    @Test
       public void testDoubleStar() throws Exception {
           URI request = createRequest(ST_READ, URI.create("file:///home/asgaard/th"));
           assert getPR().resolve(request) == null;

        request = createRequest(ST_READ, URI.create("file:///home/asgaard/thor"));
        assert getPR().resolve(request) != null;

        request = createRequest(ST_READ, URI.create("file:///home/asgaard/thor/"));
        assert getPR().resolve(request) != null;

        request = createRequest(ST_READ, URI.create("file:///home/asgaard/thorazine"));
        assert getPR().resolve(request) == null;

        request = createRequest(ST_READ, URI.create("file:///home/asgaard/thor/bax/fnord"));
        assert getPR().resolve(request) != null;
       }

    @Test
    public void testFactory() throws Exception{
        JSONObject cfg = new JSONObject();
        cfg.put(STFunctorClaimTypes.ACCESS.getValue(), getTemplates());
        STClaimsHandler handler = new STClaimsHandler(cfg);
        handler.process(new HashMap<String, Object>());
        assert !handler.getTemplates().isEmpty();
    }
}
