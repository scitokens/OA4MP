package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServletUtil;

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
}
