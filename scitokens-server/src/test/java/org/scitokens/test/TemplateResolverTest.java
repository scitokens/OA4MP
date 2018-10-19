package org.scitokens.test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.GroupElement;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.Groups;
import org.junit.Test;
import org.scitokens.util.claims.AuthorizationPath;
import org.scitokens.util.claims.AuthorizationTemplate;
import org.scitokens.util.claims.AuthorizationTemplates;
import org.scitokens.util.claims.TemplateResolver;

import java.util.LinkedList;
import java.util.List;

import static org.scitokens.util.SciTokensClaims.CLAIM_OPERATION_READ;
import static org.scitokens.util.SciTokensClaims.CLAIM_OPERATION_WRITE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/11/18 at  6:22 PM
 */
public class TemplateResolverTest {
    public static String AUDIENCE_1 = "https://demo.foo.bar";
    public static String PATH_1_READ = "/public/dataset/**";
    public static String PATH_1_WRITE = "/public/dataset/**";
    public static String READ_1_TEST = "/public/dataset/xy";
    public static String WRITE_1_TEST = "/public/dataset/xy/foo.data";

    public static String AUDIENCE_2 = "https://demo.foo.bar/**";
    public static String AUDIENCE_2_TEST = "https://demo.foo.bar/server";
    public static String PATH_2_READ = "/public/dataset/${" + TemplateResolver.ST_USER_NAME + "}/**";
    public static String PATH_2_WRITE = "/public/dataset/${" + TemplateResolver.ST_GROUP_NAME + "}/**";
    public static String READ_2_TEST = "/public/dataset/bob/xy"; // bob is the user name
    public static String WRITE_2_TEST = "/public/dataset/my-group/foo.data"; // my-group is the group name

    protected Groups getTestGroups() {
        Groups groups = new Groups();
        groups.put(new GroupElement("my-group"));
        groups.put(new GroupElement("test-group2"));
        groups.put(new GroupElement("asgaard"));
        return groups;
    }

    protected AuthorizationTemplates getTemplates() {
        AuthorizationTemplates authorizationTemplates = new AuthorizationTemplates();
        LinkedList<AuthorizationPath> paths = new LinkedList<>();
        paths.add(new AuthorizationPath(CLAIM_OPERATION_READ, PATH_1_READ));
        paths.add(new AuthorizationPath(CLAIM_OPERATION_WRITE, PATH_1_WRITE));
        AuthorizationTemplate authorizationTemplate = new AuthorizationTemplate(AUDIENCE_1, paths);
        authorizationTemplates.put(authorizationTemplate);

        // next batch of these, with a group and user in the templates
        paths = new LinkedList<>();
        paths.add(new AuthorizationPath(CLAIM_OPERATION_READ, PATH_2_READ));
        paths.add(new AuthorizationPath(CLAIM_OPERATION_WRITE, PATH_2_WRITE));
        authorizationTemplate = new AuthorizationTemplate(AUDIENCE_2, paths);
        authorizationTemplates.put(authorizationTemplate);


        return authorizationTemplates;
    }

    @Test
    public void testBasic() throws Exception {
        TemplateResolver templateResolver = new TemplateResolver("bob", getTestGroups());
        AuthorizationTemplates at = getTemplates();
        AuthorizationTemplate template = at.get(AUDIENCE_1);
        assert templateResolver.check(template.getAudience(), AUDIENCE_1);

        // Most basic test to show this works.
        assert templateResolver.check(PATH_1_READ, READ_1_TEST);
        assert templateResolver.check(PATH_1_WRITE, WRITE_1_TEST);
    }

    /**
     * For the case that the user is not in any groups. None of the group templates should be
     * resolved against.
     * @throws Exception
     */

    @Test
       public void testNoGroups() throws Exception {
           TemplateResolver templateResolver = new TemplateResolver("bob", new Groups());
           AuthorizationTemplates at = getTemplates();
           AuthorizationTemplate template = at.get(AUDIENCE_1);
           assert templateResolver.check(template.getAudience(), AUDIENCE_1);

           // Most basic test to show this works.
           assert templateResolver.check(PATH_1_READ, READ_1_TEST);
           assert templateResolver.check(PATH_1_WRITE, WRITE_1_TEST);
       }

    @Test
    public void testUserAndGroup() throws Exception {
        TemplateResolver templateResolver = new TemplateResolver("bob", getTestGroups());
        AuthorizationTemplates at = getTemplates();
        AuthorizationTemplate template = at.get(AUDIENCE_2);

        assert templateResolver.check(template.getAudience(), AUDIENCE_2_TEST);
        assert !templateResolver.check(template.getAudience(), "fnord");

        assert templateResolver.check(PATH_2_READ, READ_2_TEST);
        assert templateResolver.check(PATH_2_WRITE, WRITE_2_TEST);
        assert !templateResolver.check(PATH_2_WRITE, "foo");
    }

    @Test
    public void testResolve() throws Exception {
        TemplateResolver templateResolver = new TemplateResolver("bob", getTestGroups());
        LinkedList<String> targets = new LinkedList<>();
        targets.add(CLAIM_OPERATION_READ + ":" + READ_1_TEST);
        List<String> scopes = templateResolver.resolve(getTemplates(), AUDIENCE_1, targets);
        assert scopes.size() == 1;
        assert scopes.get(0).equals(CLAIM_OPERATION_READ + ":" + READ_1_TEST);
    }


}
