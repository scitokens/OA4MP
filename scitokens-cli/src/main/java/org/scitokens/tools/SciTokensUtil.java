package org.scitokens.tools;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.*;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.Commands;
import edu.uiuc.ncsa.security.util.cli.ConfigurableCommandsImpl;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.functor.parser.event.ParserUtil;
import org.apache.commons.lang.StringUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.List;
import java.util.Vector;

import static edu.uiuc.ncsa.security.util.cli.CommonCommands.BATCH_MODE_FLAG;

/**
 * This creates SciTokens at the command line from the utilities and can verify them as well.
 * It also will generate signing keys.
 * <p>Created by Jeff Gaynor<br>
 * on 9/5/17 at  3:31 PM
 */
public class SciTokensUtil extends ConfigurableCommandsImpl {
    public SciTokensUtil(MyLoggingFacade logger) {
        super(logger);
    }

    public void about() {
        int width = 60;
        String stars = StringUtils.rightPad("", width + 1, "*");
        say(stars);
        say(padLineWithBlanks("* SciTokens CLI (Command Line Interpreter)", width) + "*");
        say(padLineWithBlanks("* Version " + LoggingConfigLoader.VERSION_NUMBER, width) + "*");
        say(padLineWithBlanks("* By Jeff Gaynor  NCSA", width) + "*");
        say(padLineWithBlanks("*  (National Center for Supercomputing Applications)", width) + "*");
        say(padLineWithBlanks("*", width) + "*");
        say(padLineWithBlanks("* type 'help' for a list of commands", width) + "*");
        say(padLineWithBlanks("*      'exit' or 'quit' to end this session.", width) + "*");
        say(stars);
    }


    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return null;
    }

    @Override
    public String getPrompt() {
        return "sciTokens>";
    }

    @Override
    public String getComponentName() {
        return null;
    }

    @Override
    public void useHelp() {
        say("You may use this in both interactive mode and as a command line utility.");
        say("To use in batch mode, supply the " + BATCH_MODE_FLAG + " flag.");
        say("This will suppress all output and will not prompt for missing arguments to functions.");
        say("If you omit this flag, then missing arguments will still cause you to be prompted.");
        say("Here is a list of commands:");
        say("Key commands");
        say("------------");
        say("create_keys");
        say("set_keys");
        say("list_keys");
        say("list_key_ids");
        say("set_default_id");
        say("print_default_id");
        say("print_well_known");
        say("Claim Commands");
        say("--------------");
        say("create_claims");
        say("parse_claims");
        say("Token Commands");
        say("--------------");
        say("create_token");
        say("print_token");
        say("validate_token");
        say("To get a full explanation of the command and its syntax, type \"command --help \".");
        say("Command line options");
        say("--------------------");
        say("These are flags and arguments to the command line processor.");
        say(SHORT_VERBOSE_FLAG + "," +  LONG_VERBOSE_FLAG + "= turn verbose mode on. This allows you to see the internal workings of processing");
        say("   You can set this in a batch file by invoking set_verbose true|false");
        say(SHORT_NO_OUTPUT_FLAG + ", " +LONG_NO_OUTPUT_FLAG + " = turn off all output");
        say("   You can set this in a batch file by invoking set_no_ouput true|false");
        say(BATCH_MODE_FLAG + "= interpret everything else on the command line as a command, aside from flags. Note this means you can execute a single command.");
        say(SciTokensUtilCommands.BATCH_FILE_MODE_FLAG + "= this is the fully qualified path to a file of commands which will be interpreted one after the other.");
    }



    protected static String DUMMY_FUNCTION = "dummy0"; // used to create initial command line

    public static String SHORT_HELP_FLAG = "-help";
    public static String LONG_HELP_FLAG = "--help";
    public static String SHORT_VERBOSE_FLAG = "-v";
    public static String LONG_VERBOSE_FLAG = "--verbose";
    public static String SHORT_NO_OUTPUT_FLAG = "-noOuput";
    public static String LONG_NO_OUTPUT_FLAG = "--noOuput";


    public static void main(String[] args) {
        Vector<String> vector = new Vector<>();
        vector.add(DUMMY_FUNCTION); // Dummay zero-th arg.
        for (String arg : args) {
            vector.add(arg);
        }
        InputLine argLine = new InputLine(vector); // now we have a bunch of utilities for this

        // In order of importance for command line flags.

        if (argLine.hasArg(SHORT_HELP_FLAG) || argLine.hasArg(LONG_HELP_FLAG)) {
            SciTokensUtil sciTokensCLI = new SciTokensUtil(null); // no logging, just grab the help and exit;
            sciTokensCLI.useHelp();
            return;
        }

        boolean isVerbose = argLine.hasArg(SHORT_VERBOSE_FLAG) || argLine.hasArg(LONG_VERBOSE_FLAG);
        // again, a batch file means every line in the file is a separate comamand, aside from comments
        boolean hasBatchFile = argLine.hasArg(SciTokensUtilCommands.BATCH_FILE_MODE_FLAG);
        // Batch mode means that the command line is interpreted as a single command. This execeuts one command, batch mode does many.
        boolean isBatchMode = argLine.hasArg(SciTokensUtilCommands.BATCH_MODE_FLAG);
       boolean isNoOuput = (argLine.hasArg(SHORT_NO_OUTPUT_FLAG) || argLine.hasArg(LONG_NO_OUTPUT_FLAG));

        MyLoggingFacade myLoggingFacade = null;
        if (argLine.hasArg("-log")) {
            String logFileName = argLine.getNextArgFor("-log");
            LoggerProvider loggerProvider = new LoggerProvider(logFileName,
                    "SciTokensUtil logger", 1, 1000000, false, isVerbose, false);
            myLoggingFacade = loggerProvider.get(); // if verbose
        }

        SciTokensUtil sciTokensCLI = new SciTokensUtil(myLoggingFacade);
        sciTokensCLI.useHelp();
        SciTokensUtilCommands sciTokensCommands = new SciTokensUtilCommands(myLoggingFacade);
        sciTokensCommands.setVerbose(isVerbose);
        sciTokensCommands.setPrintOuput(!isNoOuput);
        try {
            CLIDriver cli = new CLIDriver(sciTokensCommands);
            // Easy case -- no arguments, so just start.
            if (args == null || args.length == 0) {
                sciTokensCLI.about();
                cli.start();
                return;
            }
            sciTokensCommands.setBatchMode(false);
            if (argLine.hasArg(SciTokensUtilCommands.BATCH_FILE_MODE_FLAG)) {
                sciTokensCLI.processBatchFile(argLine.getNextArgFor(SciTokensUtilCommands.BATCH_FILE_MODE_FLAG), cli);
                return;
            }
            if (argLine.hasArg(BATCH_MODE_FLAG)) {
                sciTokensCLI.processBatchModeCommand(cli, args);
            }
            // alternately, parse the arguments
            String cmdLine = args[0];
            for (int i = 1; i < args.length; i++) {
                if (args[i].equals(BATCH_MODE_FLAG)) {
                    sciTokensCommands.setBatchMode(true);
                } else {
                    // don't keep the batch flag in the final arguments.
                    cmdLine = cmdLine + " " + args[i];
                }
            }
            cli.execute(cmdLine);

        } catch (Throwable t) {
            if (sciTokensCommands.isBatchMode()) {
                System.exit(1);
            }
            t.printStackTrace();
        }
    }

    protected SciTokensUtilCommands getSciTokensCommands(CLIDriver cli) {
        for (Commands c : cli.getCLICommands()) {
            if (c instanceof SciTokensUtilCommands) {
                return (SciTokensUtilCommands) c;
            }
        }

        return null;
    }

    protected void processBatchModeCommand(CLIDriver cli, String[] args) throws Exception {
        SciTokensUtilCommands sciTokensCommands = getSciTokensCommands(cli);
        if (sciTokensCommands == null) {
            throw new NFWException("Error: No SciTokensUtilCommands configured, hence no logging.");
        }
        sciTokensCommands.setBatchMode(true);
        // need to tease out the intended line to execute. The arg line looks like
        // sciTokens -batch A B C
        // so we need to drop the name of the function and the -batch flag.
        String cmdLine = "";
        for (String arg : args) {
            if (!arg.equals(DUMMY_FUNCTION) && !arg.equals(SciTokensUtilCommands.BATCH_FILE_MODE_FLAG)) {

                cmdLine = cmdLine + " " + arg;
            }
        }
        cli.execute(cmdLine);
    }


    protected void processBatchFile(String fileName, CLIDriver cli) throws Throwable {
        if(fileName == null || fileName.isEmpty()){
            throw new FileNotFoundException("Error: The file name is missing.");
        }
        File file = new File(fileName);
        if (!file.exists()) {
            throw new FileNotFoundException("Error: The file \"" + fileName + "\" does not exist");
        }
        if (!file.isFile()) {
            throw new FileNotFoundException("Error: The object \"" + fileName + "\" is not a file.");
        }
        if (!file.canRead()) {
            throw new GeneralException("Error: Cannot read file \"" + fileName + "\". Please check your permissions.");
        }
        FileReader fis = new FileReader(file);
        List<String> commands = ParserUtil.processInput(fis);
        SciTokensUtilCommands sciTokensCommands = getSciTokensCommands(cli);
        if (sciTokensCommands == null) {
            throw new NFWException("Error: No SciTokensUtilCommands configured, hence no logging.");
        }
        sciTokensCommands.setBatchMode(true);

        for(String command : commands){
            try {
                       int rc = cli.execute(command);
                       switch (rc) {
                           // Hint: The colons in the messages line up (more or less) so that the log file is very easily readable at a glance.
                           case CLIDriver.ABNORMAL_RC:
                                   sciTokensCommands.error("Error: \"" +  command + "\"");
                               break;
                           case CLIDriver.HELP_RC:
                                   sciTokensCommands.info("  Help: invoked.");
                               break;
                           case CLIDriver.OK_RC:
                           default:
                               if(sciTokensCommands.isVerbose()){
                                   sciTokensCommands.info("    ok: \"" + command+ "\"");
                               }
                       }

                   } catch (Throwable t) {
                       sciTokensCommands.error(t, "Error executing batch file command \"" + command + "\"");
                   }

        }

    }

    protected void start(String[] args) throws Exception {
        about();
        if (!getOptions(args)) {
            say("Warning: no configuration file specified. type in 'load --help' to see how to load one.");
            return;
        }
    }


}
