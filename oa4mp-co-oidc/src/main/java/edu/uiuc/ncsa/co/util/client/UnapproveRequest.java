package edu.uiuc.ncsa.co.util.client;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/2/16 at  11:53 AM
 */
public class UnapproveRequest extends ClientRequest {
    public UnapproveRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }
}