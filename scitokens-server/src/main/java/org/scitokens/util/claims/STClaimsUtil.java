package org.scitokens.util.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import org.scitokens.util.STTransaction;

import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/14/20 at  3:02 PM
 */
public class STClaimsUtil extends OA2ClaimsUtil {
    public STClaimsUtil(OA2SE oa2se, OA2ServiceTransaction transaction) {
        super(oa2se, transaction);
    }

    @Override
    protected ScriptRunRequest newSRR(OA2ServiceTransaction transaction, String phase) {
        STTransaction t = (STTransaction)transaction;
        ScriptRunRequest srr =  super.newSRR(transaction, phase);
              //    t.setVersion();
        return srr ;
    }

    @Override
    protected void handleSREResponse(ScriptRunResponse scriptRunResponse) throws IOException {
        super.handleSREResponse(scriptRunResponse);
    }
}



