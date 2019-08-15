package com.ddphin.security.authenticator;

import com.ddphin.security.entity.AIdentity;
import com.ddphin.security.endpoint.service.AuthenticationService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * AIdentityAuthenticator
 *
 * @Date 2019/7/17 下午3:08
 * @Author ddphin
 */
public interface AIdentityAuthenticator {

    Authentication authenticate(Authentication authentication,
                                AuthenticationService authenticationService) throws AuthenticationException;

    AIdentity supports();
}
