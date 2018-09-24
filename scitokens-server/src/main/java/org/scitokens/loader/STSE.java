package org.scitokens.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyFacadeProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AuthorizationServletConfig;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.servlet.UsernameTransformer;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.mail.MailUtilProvider;

import javax.inject.Provider;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/2/18 at  8:10 AM
 */
public class STSE extends OA2SE {
    public STSE(MyLoggingFacade logger,
                Provider<TransactionStore> tsp,
                Provider<ClientStore> csp,
                int maxAllowedNewClientRequests,
                long rtLifetime,
                Provider<ClientApprovalStore> casp,
                List<MyProxyFacadeProvider> mfp,
                MailUtilProvider mup,
                MessagesProvider messagesProvider,
                Provider<AGIssuer> agip,
                Provider<ATIssuer> atip,
                Provider<PAIssuer> paip,
                Provider<TokenForge> tfp,
                HashMap<String, String> constants,
                AuthorizationServletConfig ac,
                UsernameTransformer usernameTransformer,
                boolean isPingable,
                Provider<PermissionsStore> psp,
                Provider<AdminClientStore> acs,
                int clientSecretLength, Collection<String> scopes,
                ClaimSource claimSource,
                LDAPConfiguration ldapConfiguration2,
                boolean isRefreshTokenEnabled,
                boolean twoFactorSupportEnabled,
                long maxClientRefreshTokenLifetime,
                JSONWebKeys jsonWebKeys,
                String issuer,
                boolean utilServletEnabled,
                boolean isATasSTEnabled,
                boolean isOIDCEnabled) {
        super(logger,
                tsp,
                csp,
                maxAllowedNewClientRequests,
                rtLifetime,
                casp,
                mfp,
                mup,
                messagesProvider,
                agip,
                atip,
                paip,
                tfp,
                constants,
                ac,
                usernameTransformer,
                isPingable,
                psp,
                acs,
                clientSecretLength,
                scopes,
                claimSource,
                ldapConfiguration2,
                isRefreshTokenEnabled,
                twoFactorSupportEnabled,
                maxClientRefreshTokenLifetime,
                jsonWebKeys, issuer,
                utilServletEnabled,
                isOIDCEnabled);

        this.isATasSTEnabled = isATasSTEnabled;
    }

    boolean isATasSTEnabled = false;

    public boolean isATasSTEnabled() {
        return isATasSTEnabled;
    }

    public void setIsATasSTEnabled(boolean isATasSTEnabled) {
        this.isATasSTEnabled = isATasSTEnabled;
    }

}
