package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServlet;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import org.scitokens.util.STTransaction;

import java.util.ArrayList;
import java.util.Map;
import java.util.StringTokenizer;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.SCOPE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  3:22 PM
 */
public class STAuthorizedServlet extends OA2AuthorizedServlet {
    @Override
    protected ArrayList<String> resolveScopes(OA2ServiceTransaction st, Map<String, String> params, String state, String givenRedirect) {
        STTransaction stTransaction = (STTransaction) st;
        System.err.println(getClass().getSimpleName() + ": scopes before resolveScopes = " + st.getScopes());
        System.err.println(getClass().getSimpleName() + ": STscopes before resolveScopes = " + ((STTransaction) st).getStScopes());

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
