package org.scitokens.tools;

import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2Commands;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/18/19 at  5:06 PM
 */
public class STCommands extends OA2Commands {
    public STCommands(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public String getPrompt() {
        return "cli>";
    }


    public static void main(String[] args) {
        try {
            STCommands stCommands = new STCommands(null);
            stCommands.start(args); // read the command line options and such to set the state
            CLIDriver cli = new CLIDriver(stCommands); // actually run the driver that parses commands and passes them along
            cli.start();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

}
