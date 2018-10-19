package org.scitokens.test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfigurationUtil;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.util.TestBase;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.junit.Test;
import org.scitokens.util.STClient;
import org.scitokens.util.STClientConfigurationUtil;
import org.scitokens.util.claims.AuthorizationPath;
import org.scitokens.util.claims.AuthorizationTemplate;
import org.scitokens.util.claims.AuthorizationTemplates;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.LinkedList;

import static org.scitokens.util.SciTokensClaims.CLAIM_OPERATION_READ;
import static org.scitokens.util.SciTokensClaims.CLAIM_OPERATION_WRITE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/13/18 at  2:12 PM
 */
public class ConfigurationTest extends TestBase {

    protected JSONObject getTestConfig() throws IOException {
        //URL url = this.getClass().getResource("src/test/resources/minimal.json");
        //File minimal = new File("src/test/resources/minimal.json");
        File minimal = new File("/home/ncsa/dev/scitokens-git/scitokens-java/scitokens-server/src/main/resources/minimal.json");
        FileReader rf = new FileReader(minimal);
        BufferedReader br = new BufferedReader(rf);
        String input = br.readLine();
        StringBuffer stringBuffer = new StringBuffer();
        while (input != null) {
            stringBuffer.append(input);
            input = br.readLine();
        }
        br.close();
        return JSONObject.fromObject(stringBuffer.toString());
    }

    protected AuthorizationTemplates getTestTemplates() {
        String audience = "https://demo.lsst.org";
        AuthorizationTemplates ats = new AuthorizationTemplates();
        LinkedList<AuthorizationPath> aps = new LinkedList<>();
        AuthorizationPath ap = new AuthorizationPath(CLAIM_OPERATION_READ, "/home/${user}");
        aps.add(ap);
        ap = new AuthorizationPath(CLAIM_OPERATION_WRITE, "/home/${user}");
        aps.add(ap);
        AuthorizationTemplate at = new AuthorizationTemplate(audience, aps);
        ats.put(at);
        System.err.println("Authorization templates:");
        System.err.println(ats.toJSON().toString(2));
        return ats;
    }

    /**
     * Create a configuration, see that it gets written.
     * @throws Exception
     */
    @Test
    public void testConfig() throws Exception {
        JSONObject cfg = getTestConfig();
        STClient client = new STClient(BasicIdentifier.newID("test:/id/" + System.currentTimeMillis()));
        client.setConfig(cfg);
        JSONArray array  = OA2ClientConfigurationUtil.getClaimSourceConfigurations(cfg);
        assert array.size() == 1;
        LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();
        client.setLdaps(ldapConfigurationUtil.fromJSON(array));

        // now we are ready to roll.
        STClientConfigurationUtil.setAuthorizationTemplates(client.getConfig(), getTestTemplates());
        assert client.getUsernameClaimKey().equals("key123");
        assert client.getLdaps().size() == 1;
        assert client.getLdaps().iterator().next().getId().equals("c82f7d6053c464ea");
    }

    /**
     * Round trip a configuration containing templates to the config file.
     * @throws Exception
     */
    @Test
    public void testReadWrite() throws Exception {
        JSONObject cfg = getTestConfig();
        STClient client = new STClient(BasicIdentifier.newID("test:/id/" + System.currentTimeMillis()));
        client.setConfig(cfg);
        AuthorizationTemplates ats = getTestTemplates();
        STClientConfigurationUtil.setAuthorizationTemplates(client.getConfig(), ats);
        assert ats.equals(STClientConfigurationUtil.getAuthorizationTemplates(client.getConfig()));
    }
}
