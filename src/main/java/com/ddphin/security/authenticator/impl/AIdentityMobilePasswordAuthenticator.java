package com.ddphin.security.authenticator.impl;

import com.ddphin.security.authenticator.AIdentityAuthenticator;
import com.ddphin.security.endpoint.entity.ACredential;
import com.ddphin.security.endpoint.service.AuthenticationService;
import com.ddphin.security.endpoint.entity.AIdentifier;
import com.ddphin.security.entity.AIdentity;
import com.ddphin.security.token.AIdentityAuthenticationToken;
import com.ddphin.security.entity.ACredentialType;
import com.ddphin.security.entity.AIdentifierType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;

/**
 * AIdentityMobilePasswordAuthenticator
 *
 * @Date 2019/7/17 下午8:36
 * @Author ddphin
 */
public class AIdentityMobilePasswordAuthenticator extends AIdentityAbstractAuthenticator implements AIdentityAuthenticator {
    @Override
    public Authentication doAuthentication(
            Authentication authentication,
            AuthenticationService authenticationService) throws AuthenticationException {
        AIdentity aIdentity = (AIdentity) authentication.getDetails();

        AIdentifier uIdentifier =  authenticationService.queryIdentifier(aIdentity.getIdentifierType(), aIdentity.getIdentifierValue());
        if (null != uIdentifier) {
            ACredential uCredential =  authenticationService.queryCredential(uIdentifier.getUserId(), aIdentity.getCredentialType());
            if (null != uCredential && new BCryptPasswordEncoder().matches(aIdentity.getCredentialValue(), uCredential.getCredentialValue())) {
                aIdentity.setUserId(uIdentifier.getUserId());
                List<String> permissionIdList = authenticationService.queryPermissionIdList(aIdentity.getUserId());
                return new AIdentityAuthenticationToken(aIdentity, permissionIdList);
            }
        }

        throw new BadCredentialsException("Authentication Failed");
    }

    @Override
    public AIdentity supports() {
        AIdentity aIdentity = new AIdentity();
        aIdentity.setIdentifierType(AIdentifierType.MOBILE.ordinal());
        aIdentity.setCredentialType(ACredentialType.PASSWORD.ordinal());
        return aIdentity;
    }
}
