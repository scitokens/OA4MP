package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.HTTPHeaderClaimsSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServletUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import org.apache.http.HttpStatus;
import org.scitokens.util.STClient;
import org.scitokens.util.STTransaction;
import org.scitokens.util.TokenExchangeConstants;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Map;
import java.util.StringTokenizer;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.SCOPE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  3:22 PM
 */
public class STAuthorizedServletUtil extends OA2AuthorizedServletUtil {
    public STAuthorizedServletUtil(MyProxyDelegationServlet servlet) {
        super(servlet);
    }

    @Override
    public void postprocess(TransactionState state) throws Throwable {
        super.postprocess(state);
        STTransaction stTransaction = (STTransaction) state.getTransaction();
        // Audience
        String rawAudience = state.getRequest().getParameter(TokenExchangeConstants.RESOURCE);
        StringTokenizer stringTokenizer = new StringTokenizer(rawAudience, " ");
        LinkedList<String> audience = new LinkedList<>();
        while (stringTokenizer.hasMoreElements()) {
            audience.add(stringTokenizer.nextToken().trim());
        }
        if (audience.size() == 0) {
            // try to special case it
            STClient client = (STClient) stTransaction.getClient();
            if (client.getAuthorizationTemplates().size() == 1) {
                // Special case. They have configured exactly one audience claim, so they may omit it and we
                // will pull it out of their configuration and supply it. They do not need to
                // send it along in the request. This fails if they ever configure a second template though (as it should).
                audience.add(client.getAuthorizationTemplates().keySet().iterator().next());
            } else {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "missing audience request", HttpStatus.SC_BAD_REQUEST);
            }
        }
        stTransaction.setAudience(audience);
        servlet.getTransactionStore().save(stTransaction);
    }

    @Override
    protected ArrayList<String> resolveScopes(OA2ServiceTransaction st, Map<String, String> params, String state, String givenRedirect) {
        HTTPHeaderClaimsSource xx = null;
        STTransaction stTransaction = (STTransaction) st;
        DebugUtil.dbg(this, "scopes before resolveScopes = " + st.getScopes());
        DebugUtil.dbg(this, "STscopes before resolveScopes = " + ((STTransaction) st).getStScopes());

        String rawScopes = params.get(SCOPE);
        if (rawScopes == null || rawScopes.length() == 0) {
            return new ArrayList<String>();
        }
        stTransaction.setStScopes(rawScopes);
        StringTokenizer stringTokenizer = new StringTokenizer(rawScopes);
        ArrayList<String> scopes = new ArrayList<>();
        while (stringTokenizer.hasMoreTokens()) {
            String x = stringTokenizer.nextToken();
            scopes.add(x);
        }
        System.err.println(getClass().getSimpleName() + ": found scopes = " + scopes);
        st.setScopes(scopes);
        return scopes;
    }

    @Override
    protected OA2ServiceTransaction createNewTransaction(AuthorizationGrant grant) {
        return new STTransaction(grant);
    }
}
