package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2RegistrationServlet;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import net.sf.json.JSONObject;
import org.scitokens.util.STClient;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/12/18 at  5:54 AM
 */
public class STRegistrationServlet extends OA2RegistrationServlet {
    public static final String CONFIGURATION = "configuration";

    @Override
    public void prepare(PresentableState state) throws Throwable {
        super.prepare(state);
        if (state.getState() == INITIAL_STATE) {
            state.getRequest().setAttribute(CONFIGURATION, CONFIGURATION);
        }

    }

    @Override
    protected Client setupNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        STClient client = (STClient) super.setupNewClient(request, response);
        String configuration = getParameter(request, CONFIGURATION);
        if (configuration != null && configuration.length() != 0) {
            JSONObject json = JSONObject.fromObject(configuration);
            client.setConfig(json);
        }
        getOA2SE().getClientStore().save(client);
        return client;
    }
}
