package org.scitokens.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.DSTransactionProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.scitokens.util.STClient;
import org.scitokens.util.STTransaction;
import org.scitokens.util.STTransactionConverter;
import org.scitokens.util.STTransactionKeys;

import javax.inject.Provider;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider.TRANSACTION_ID;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME_SPECIFIC_PART;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  11:15 AM
 */
public class STLoader<T extends STSE> extends OA2ConfigurationLoader<T> {

    public static final String ISSUE_AT_AS_SCI_TOKEN = "issueATasSciToken";

    public STLoader(ConfigurationNode node) {
        super(node);
    }

    public STLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }

    @Override
    public T createInstance() {
        try {
            T se = (T) new STSE(loggerProvider.get(),
                    getTransactionStoreProvider(),
                    getClientStoreProvider(),
                    getMaxAllowedNewClientRequests(),
                    getRTLifetime(),
                    getClientApprovalStoreProvider(),
                    getMyProxyFacadeProvider(),
                    getMailUtilProvider(),
                    getMP(),
                    getAGIProvider(),
                    getATIProvider(),
                    getPAIProvider(),
                    getTokenForgeProvider(),
                    getConstants(),
                    getAuthorizationServletConfig(),
                    getUsernameTransformer(),
                    getPingable(),
                    getMpp(),
                    getMacp(),
                    getClientSecretLength(),
                    getScopes(),
                    getClaimSource(),
                    getLdapConfiguration(),
                    isRefreshTokenEnabled(),
                    isTwoFactorSupportEnabled(),
                    getMaxClientRefreshTokenLifetime(),
                    getJSONWebKeys(),
                    getIssuer(),
                    isUtilServerEnabled(),
                    issueSciTokenForAT(),
                    isOIDCEnabled());
            if (getClaimSource() instanceof BasicClaimsSourceImpl) {
                ((BasicClaimsSourceImpl) getClaimSource()).setOa2SE(se);
            }
            return se;
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            throw new GeneralException("Error: Could not create the runtime environment", e);
        }
    }

    public static class STTProvider extends DSTransactionProvider<STTransaction> {

        public STTProvider(IdentifierProvider<Identifier> idProvider) {
            super(idProvider);
        }

        @Override
        public STTransaction get(boolean createNewIdentifier) {
            return new STTransaction(createNewId(createNewIdentifier));
        }
    }

    Boolean issueSciTokenForAT = null;

    /**
     * Determines if this server will issue a simple access token (standard OA4MP) or a full blown SciToken as its access token.
     * The token exchange endpoint always allows a user to get a SciToken.
     *
     * @return
     */
    public boolean issueSciTokenForAT() {
        if (issueSciTokenForAT == null) {
            String x = Configurations.getFirstAttribute(this.cn, ISSUE_AT_AS_SCI_TOKEN);
            issueSciTokenForAT = false;
            try {
                issueSciTokenForAT = Boolean.parseBoolean(x);
            } catch (Throwable t) {
                info("Error: Could not interpret attribute for setting " + ISSUE_AT_AS_SCI_TOKEN + ". Using default of false");
            }
        }
        return issueSciTokenForAT;
    }

    @Override
    protected Provider<TransactionStore> getTSP() {
        STTProvider tp = new STTProvider(new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, TRANSACTION_ID, false));
        STTransactionKeys keys = new STTransactionKeys();
        STTransactionConverter<STTransaction> tc = new STTransactionConverter<STTransaction>(keys,
                tp,
                getTokenForgeProvider().get(),
                getClientStoreProvider().get());
        return getTSP(tp, tc);

    }

    public static class STClientProvider<V extends OA2Client> extends OA2ClientProvider {
        public STClientProvider(IdentifierProvider idProvider) {
            super(idProvider);
        }
        @Override
    protected V newClient(boolean createNewIdentifier) {
       return (V) new STClient(createNewId(createNewIdentifier));
    }

    }
    @Override
    public IdentifiableProvider<? extends Client> getClientProvider() {
            return new STClientProvider(new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, OA2Constants.CLIENT_ID, false));
    }
}
