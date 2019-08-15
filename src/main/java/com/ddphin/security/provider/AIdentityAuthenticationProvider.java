package com.ddphin.security.provider;

import com.ddphin.security.authenticator.AIdentityAuthenticator;
import com.ddphin.security.endpoint.service.AuthenticationService;
import com.ddphin.security.authenticator.AIdentityAuthenticatorHolder;
import com.ddphin.security.entity.AIdentity;
import com.ddphin.security.token.AIdentityAuthenticationToken;
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

    public AIdentityAuthenticationProvider(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AIdentity identity = (AIdentity) authentication.getDetails();
        AIdentityAuthenticator authenticator = AIdentityAuthenticatorHolder.get(identity);

        return authenticator.authenticate(authentication, authenticationService);
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return AIdentityAuthenticationToken.class.isAssignableFrom(aClass);
    }
}
