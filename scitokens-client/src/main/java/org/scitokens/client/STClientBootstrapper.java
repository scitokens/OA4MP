package org.scitokens.client;

import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientBootstrapper;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/17/19 at  3:06 PM
 */
public class STClientBootstrapper extends OA2ClientBootstrapper {
    public static final String ST_CLIENT_CONFIG_FILE_KEY= "scitokens:client.config.file";
    public static final String ST_CLIENT_CONFIG_NAME_KEY= "scitokens:client.config.name";
    @Override
    public String getOa4mpConfigFileKey() {
        return ST_CLIENT_CONFIG_FILE_KEY;
    }

    @Override
    public String getOa4mpConfigNameKey() {
        return ST_CLIENT_CONFIG_NAME_KEY;
    }
}
