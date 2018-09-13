package org.scitokens.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oauth2.tools.SigningCommands;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;

import java.io.File;
import java.io.FileWriter;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/1/18 at  9:20 AM
 */
public class STSigningCommands extends SigningCommands {
    public STSigningCommands(OA2SE oa2se) {
        super(oa2se);
    }

    // TODO THIS method should replace the one in the parent class and that class should go away. This is a bug fix we can't get into OA4MP 4.0.1 in time
    @Override
    public void create(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            createHelp();
            return;
        }
        //PublicKey publicKey = KeyUtil.g
        boolean retry = true;
        File publicKeyFile = null;

        if (1 < inputLine.size()) {
            publicKeyFile = new File(inputLine.getArg(1));
        }
        if (publicKeyFile == null && isBatchMode()) {
            throw new GeneralException("No full path to the file given.");
        }

        if (!isBatchMode()) {
            while (retry) {
                // Let's the user try to enter the correct file name and prompts if it will be over-written
                if (publicKeyFile == null) {
                    String publicKeyPath = getInput("Give the file path", "");
                    if (publicKeyPath.toLowerCase().equals("exit") || publicKeyPath.toLowerCase().equals("quit")) {
                        return;
                    }
                    publicKeyFile = new File(publicKeyPath);
                }


                if (publicKeyFile.exists()) {
                    if (!publicKeyFile.isFile()) {
                        sayi("Sorry, but you must supply the name of the file as well (or type 'exit' to exit");
                    } else {
                        sayi2("The file you gave exists, do you want to over write it? [y/n]");
                        retry = !isOk(readline());
                    }
                } else {
                    retry = false;
                }
            }
            sayi2("create a new set of JSON web keys?[y/n]");
            if (!isOk(readline())) {
                say("create cancelled.");
                return;
            }

        }


        JSONWebKeys keys = new JSONWebKeys(null);
        keys.put(createJWK("RS256"));
        keys.put(createJWK("RS384"));
        keys.put(createJWK("RS512"));
        FileWriter writer = new FileWriter(publicKeyFile);
        JSONObject jwks = JSONWebKeyUtil.toJSON(keys);
        writer.write(jwks.toString(3));
        writer.flush();
        writer.close();

        if (!isBatchMode()) {
            sayi("JSONweb keys written");
            sayi("Done!");
        }

    }

}
