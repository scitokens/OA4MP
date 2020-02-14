package org.scitokens.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CLCCommands;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CommandLineClient;
import edu.uiuc.ncsa.security.core.util.LoggingConfigLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import org.apache.commons.lang.StringUtils;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/11/17 at  10:25 AM
 */
public class STClient extends OA2CommandLineClient {
    public STClient(MyLoggingFacade logger) {
        super(logger);
    }

    public static void main(String[] args) {
        try {
            STClient testCommands = new STClient(null);
            testCommands.start(args);
            STClientCommands usc = new STClientCommands(testCommands.getMyLogger(), (ClientEnvironment) testCommands.getEnvironment());

            CLIDriver cli = new CLIDriver(usc);
            cli.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void about() {
        int width = 60;
        String stars = StringUtils.rightPad("", width + 1, "*");
        say(stars);
        say(padLineWithBlanks("* SciTokens command line test client", width) + "*");
        say(padLineWithBlanks("* Version " + LoggingConfigLoader.VERSION_NUMBER, width) + "*");
        say(padLineWithBlanks("* By Jeff Gaynor  NCSA", width) + "*");
        say(padLineWithBlanks("*  (National Center for Supercomputing Applications)", width) + "*");
        say(padLineWithBlanks("*", width) + "*");
        say(padLineWithBlanks("* type 'help' for a list of commands", width) + "*");
        say(padLineWithBlanks("*      'exit' or 'quit' to end this session.", width) + "*");
        say(stars);
    }
}
