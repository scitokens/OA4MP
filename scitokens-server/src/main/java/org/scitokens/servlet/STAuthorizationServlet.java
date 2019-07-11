package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServletUtil;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import org.scitokens.util.STTransaction;

import javax.servlet.http.HttpServletRequest;

import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/17/18 at  1:15 PM
 */
public class STAuthorizationServlet extends OA2AuthorizationServer
{
    @Override
    protected OA2AuthorizedServletUtil getInitUtil() {
        return new STAuthorizedServletUtil(this);
    }


    @Override
    protected void setClientRequestAttributes(AuthorizedState aState) {
        super.setClientRequestAttributes(aState);
        HttpServletRequest request = aState.getRequest();

        STTransaction t = (STTransaction) aState.getTransaction();
        String audience = "";
        for(String aud : t.getAudience()){
            audience = audience + " " + aud;
        }
        DebugUtil.trace(this,"Returning audience = \"" + audience+ "\"");

        request.setAttribute("clientAudience", escapeHtml(audience));

    }

}
