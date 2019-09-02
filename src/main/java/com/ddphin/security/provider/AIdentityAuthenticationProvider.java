package com.ddphin.security.provider;

import com.ddphin.security.authenticator.AIdentityAuthenticator;
import com.ddphin.security.endpoint.service.AuthenticationService;
import com.ddphin.security.authenticator.AIdentityAuthenticatorHolder;
import com.ddphin.security.entity.AIdentity;
import com.ddphin.security.token.AIdentityAuthenticationToken;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * AIdentityAuthenticationProvider
 *
 * @Date 2019/7/17 下午3:08
 * @Author ddphin
 */
public class AIdentityAuthenticationProvider implements AuthenticationProvider {
    private AuthenticationService authenticationService;
    private DataSourceTransactionManager dataSourceTransactionManager;

    public AIdentityAuthenticationProvider(
            AuthenticationService authenticationService,
            DataSourceTransactionManager dataSourceTransactionManager) {
        this.authenticationService = authenticationService;
        this.dataSourceTransactionManager = dataSourceTransactionManager;
    }
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AIdentity identity = (AIdentity) authentication.getDetails();
        AIdentityAuthenticator authenticator = AIdentityAuthenticatorHolder.get(identity);

        return authenticator.authenticate(authentication, authenticationService, dataSourceTransactionManager);
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return AIdentityAuthenticationToken.class.isAssignableFrom(aClass);
    }
}
