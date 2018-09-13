package org.scitokens.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionTable;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/2/18 at  7:23 AM
 */
public class STTransactionTable extends OA2TransactionTable {
    public STTransactionTable(OA2TransactionKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    protected STTransactionKeys getSTK(){
        return (STTransactionKeys)getOA2Keys();
    }
    public void createColumnDescriptors() {
         super.createColumnDescriptors();
         this.getColumnDescriptor().add(new ColumnDescriptorEntry(this.getSTK().sciTokens(), java.sql.Types.LONGVARCHAR));
         this.getColumnDescriptor().add(new ColumnDescriptorEntry(this.getSTK().stScopes(), java.sql.Types.LONGVARCHAR));
         this.getColumnDescriptor().add(new ColumnDescriptorEntry(this.getSTK().audience(), java.sql.Types.LONGVARCHAR));
     }
}
