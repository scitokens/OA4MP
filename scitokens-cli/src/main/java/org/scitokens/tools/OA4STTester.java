package org.scitokens.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2Tester;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/11/17 at  10:25 AM
 */
public class OA4STTester extends OA2Tester {
    public OA4STTester(MyLoggingFacade logger) {
        super(logger);
    }

    public static void main(String[] args) {
        try {
            OA4STTester testCommands = new OA4STTester(null);
            testCommands.start(args);
            STTokenCommands usc = new STTokenCommands(testCommands.getMyLogger(), (ClientEnvironment) testCommands.getEnvironment());

            CLIDriver cli = new CLIDriver(usc);
            cli.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
