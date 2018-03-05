package org.scitokens.tools;

import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.LoggingConfigLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.CommonCommands;
import edu.uiuc.ncsa.security.util.cli.ConfigurableCommandsImpl;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;

/**
 * This creates SciTokens at the command line from the utilities and can verify them as well.
 * It also will generate signing keys.
 * <p>Created by Jeff Gaynor<br>
 * on 9/5/17 at  3:31 PM
 */
public class SciTokensCLI extends ConfigurableCommandsImpl {
    public SciTokensCLI(MyLoggingFacade logger) {
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
        say("To use in batch mode, supply the " + CommonCommands.BATCH_MODE_FLAG + " flag.");
        say("This will suppress all output and will not prompt for missing arguments to functions.");
        say("If you omit this flag, then missing arguments will still cause you to be prompted.");
        say("Here is a list of commands:");
        say("create_claims");
        say("create_token");
        say("list_key_ids");
        say("list_keys");
        say("parse_claims");
        say("print_token");
        say("To get a full explanation of the command and its syntax, type \"command --help \", e.g. ");
        say("java -jar scitokens.jar -batch create_keys -- help");
        say("  create_keys filename: This will create a JWK file and the corresponding public and private key files in pem format.");
        say("                        when this is done, the following files will be create filename.jwk, filename-public.pem and" +
                "                        filename-private.pem. At this point only 512 bit signing is supported.");
        say("                        NOTE: the pem files are supplied so you can use them with other applications. This only uses the .jwk file");
        say("  set_key filename: This will set the signing and validation key from the given file");
        say("  sign string: This creates an id token from the given string.");
        say("  -");
        say("Type 'exit' when you wish to exit the component and return to the main menu");
    }


    /*
{"claims":
  {"$logic":
     {"$if":{"$and":[
                    {"$match":{"@idp","https://grid.bigstate.edu/services"}},
                    {"$endsWith":["@eppn","@ligo.org"]}
                   ]
           }
     },
     {"$then":[
         {$set:{"@aud":"https://a.b.c/ligo"}},
         {$set:{"@sub":{"$toLowerCase":"@username"}},
         ]
     }
  },
  {"$access":[
     {"read":"file:///home/@group_id/@user_id"},
     {"write":"file://a.b.c/area51/@group_id"},
     {"write":"file://p.q.r/area51/@group_id"}
     ]
  },
  {"comment":"This matchs idp and domain of the user before setting the audience and subject"}
}
 */
    public static void testJSON() throws Exception {
        JSONObject claims = new JSONObject();

        Functor andF = new Functor("$and");

        Functor matchF = new Functor("$match");

        matchF.addArg("@idp");
        matchF.addArg("https://grid.bigstate.edu/services");
        andF.addArg(matchF);

        Functor endsWithF = new Functor("$endsWith");
        endsWithF.addArg("@eppn");
        endsWithF.addArg("@ligo.org");
        andF.addArg(endsWithF);

        Functor isMemberOfF = new Functor("$isMemberOf");
        JSONArray groups = new JSONArray();
        groups.add("ligo-users");
        groups.add("ligo-group1");
        groups.add("ligo-group2");
        isMemberOfF.addArg(groups);
        andF.addArg(isMemberOfF);

        Functor thenF = new Functor("$then");
        Functor set1 = new Functor("$set");
        set1.addArg("@aud");
        set1.addArg("@https://a.b.c/ligo.org");
        thenF.addArg(set1);

        Functor set2 = new Functor("$set");
        set2.addArg("sub");
        Functor toLowerCaseF = new Functor("$toLowerCase");
        toLowerCaseF.addArg("@username");
        set2.addArg(toLowerCaseF);
        thenF.addArg(set2);

        Functor ifF = new Functor("$if");
        ifF.addArg(andF);

        System.out.println(ifF.toJSON().toString(2));
        System.out.println(thenF.toJSON().toString(2));
         claims.put(ifF.getName(), ifF.getArgs());
         claims.put(thenF.getName(), thenF.getArgs());

        Functor accessF = new Functor("$access");
        accessF.addArg(PTemplate.create("read","file:///home/@group_id/@user_id"));

        accessF.addArg(PTemplate.create("write","file://a.b.c/area51/@group_id"));
        accessF.addArg(PTemplate.create("write","file://a.b.c/area51/@group_id"));
        accessF.addArg(PTemplate.create("write","file://a.b.c/area51/@group_id/@username"));
        claims.put(accessF.getName(), accessF.getArgs());


        System.out.println(claims.toString(2));

        /*
            {"read":"file:///home/@group_id/@user_id"},
     {"write":"file://a.b.c/area51/@group_id"},
     {"write":"file://p.q.r/area51/@group_id"}

         */


    }

    public static class Functor {
        public Functor(String name) {
            setName(name);
        }

        JSONArray args = new JSONArray();

        String name;
        public void setName(String name){
                 this.name = name;
        }

        public String getName(){
            return name;
        }
        public void addArg(String x){
            args.add(x);
        }

        public void addArg(JSON x){
            args.add(x);
        }

        public void addArg(Functor x){
            args.add(x.toJSON());
        }
        public JSONObject toJSON(){
            JSONObject json = new JSONObject();
            json.put(name, args);
            return json;
        }

        public JSONArray getArgs(){
            return args;
        }

    }

    public static class PTemplate{
        public static JSONObject create(String op, String template){
            PTemplate x = new PTemplate(op, template);
            return x.toJSON();
        }
        public PTemplate(String op, String template) {
            this.op = op;
            this.template = template;
        }

        String op;
        String template;

        public String getOp() {
            return op;
        }

        public void setOp(String op) {
            this.op = op;
        }

        public String getTemplate() {
            return template;
        }

        public void setTemplate(String template) {
            this.template = template;
        }
        public JSONObject toJSON(){
            JSONObject json = new JSONObject();
            json.put(getOp(), getTemplate());
            return json;
        }
    }
    public static void main(String[] args) {
        try {
            testJSON();
            return;
        } catch (Exception x) {
            x.printStackTrace();
        }
        SciTokensCLI oa2Commands = new SciTokensCLI(null);
        SciTokensCommands sciTokensCommands = new SciTokensCommands(null);
        try {
            CLIDriver cli = new CLIDriver(sciTokensCommands);
            if (args == null || args.length == 0) {
                //oa2Commands.start(args);
                oa2Commands.about();
                cli.start();
                return;
            }
            sciTokensCommands.setBatchMode(false);
            // alternately, parse the arguments
            if (args[0].equalsIgnoreCase("--help")) {
                oa2Commands.useHelp();
                return;
            }
            String cmdLine = args[0];
            for (int i = 1; i < args.length; i++) {
                if (args[i].equals(CommonCommands.BATCH_MODE_FLAG)) {
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


    protected void start(String[] args) throws Exception {
        about();
        if (!getOptions(args)) {
            say("Warning: no configuration file specified. type in 'load --help' to see how to load one.");
            return;
        }
    }


}
