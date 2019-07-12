package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2RegistrationServlet;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import net.sf.json.JSONObject;
import org.scitokens.util.STClient;
import org.scitokens.util.STClientConfigurationUtil;
import org.scitokens.util.claims.AuthorizationPath;
import org.scitokens.util.claims.AuthorizationTemplate;
import org.scitokens.util.claims.AuthorizationTemplates;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.StringReader;
import java.util.Collection;
import java.util.LinkedList;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/12/18 at  5:54 AM
 */
public class STRegistrationServlet extends OA2RegistrationServlet {
    public static final String CONFIGURATION = "configuration";
    public static final String USER_CLAIM_KEY = "userClaimKey";
    protected static final String AUDIENCE = OA2Claims.AUDIENCE;
    protected static final String TEMPLATES = "templates";


    public static int templateCount = 4; // for reading the templates

    @Override
    public void prepare(PresentableState state) throws Throwable {
        super.prepare(state);
        if (state.getState() == INITIAL_STATE) {
            state.getRequest().setAttribute(USER_CLAIM_KEY, USER_CLAIM_KEY);
            for (int i = 0; i < templateCount; i++) {
                state.getRequest().setAttribute(AUDIENCE + i, AUDIENCE + i);
                state.getRequest().setAttribute(TEMPLATES + i, TEMPLATES + i);
            }
        }

    }

    @Override
    protected Client setupNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        STClient client = (STClient) super.setupNewClient(request, response);
        String userClaimKey = getParameter(request, USER_CLAIM_KEY);
        JSONObject stCfg = new JSONObject(); // This is the actual content of the ST claims configuration object.
        if (userClaimKey == null || userClaimKey.isEmpty()) {
            stCfg.put(STClientConfigurationUtil.USERNAME_CLAIM_KEY, OA2Claims.SUBJECT); //default
        } else {
            stCfg.put(STClientConfigurationUtil.USERNAME_CLAIM_KEY, userClaimKey); //default
        }
        AuthorizationTemplates authorizationTemplates = new AuthorizationTemplates();
        for (int i = 0; i < templateCount; i++) {
            String currentAud = getParameter(request, AUDIENCE + i);
            String currentTemplate = getParameter(request, TEMPLATES + i);
            if (currentAud == null || currentAud.isEmpty()) {
                // skip it
            } else {
                if (currentTemplate == null || currentTemplate.isEmpty()) {
                    // also skip it
                } else {
                    // only case: audience and template are both not trivial
                    // each text box contains one template per line, so iterate.
                    BufferedReader br = new BufferedReader(new StringReader(currentTemplate));
                    String x = br.readLine();
                    Collection<AuthorizationPath> aPaths = new LinkedList<>();
                    while (x != null) {
                        AuthorizationPath aPath = new AuthorizationPath(x);
                        aPaths.add(aPath);
                        x = br.readLine();
                    }

                    br.close();
                    AuthorizationTemplate authorizationTemplate = new AuthorizationTemplate(currentAud, aPaths);
                    authorizationTemplates.put(authorizationTemplate);
                }
            }
        }

        // now put it in another JSON object
        stCfg.put(STClientConfigurationUtil.AUTHORIZATION_TEMPLATES_KEY, authorizationTemplates.toJSON());
        JSONObject stTop = new JSONObject();
        stTop.put(STClientConfigurationUtil.CONFIG_KEY, "Auto generated configuration from registration");
        stTop.put(STClientConfigurationUtil.SAVED_KEY, Boolean.TRUE);
        stTop.put(STClientConfigurationUtil.SCI_TOKENS_KEY, stCfg);
        client.setConfig(stTop);
        getOA2SE().getClientStore().save(client);
        return client;
    }
}
