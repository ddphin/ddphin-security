package com.ddphin.security.authenticator.impl;

import com.ddphin.security.endpoint.service.AuthenticationService;
import com.ddphin.security.authenticator.AIdentityAuthenticator;
import com.ddphin.security.endpoint.entity.AIdentifier;
import com.ddphin.security.entity.ACredentialType;
import com.ddphin.security.entity.AIdentifierType;
import com.ddphin.security.entity.AIdentity;
import com.ddphin.security.token.AIdentityAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.List;

/**
 * AIdentityMobileValidCodeAuthenticator
 *
 * @Date 2019/7/17 下午8:36
 * @Author ddphin
 */
public class AIdentityMobileValidCodeAuthenticator implements AIdentityAuthenticator {
    @Override
    public Authentication authenticate(
            Authentication authentication,
            AuthenticationService authenticationService) throws AuthenticationException {
        AIdentity aIdentity = (AIdentity) authentication.getDetails();

        String mobile = aIdentity.getIdentifierValue();
        String validCode = authenticationService.queryValidCode(mobile);
        if (null == validCode || !validCode.equals(aIdentity.getCredentialValue())) {
            throw new BadCredentialsException("Authentication Failed");
        }
        authenticationService.removeValidCode(mobile);

        AIdentifier uIdentifier =  authenticationService.queryIdentifier(aIdentity.getIdentifierType(), mobile);

        if (null == uIdentifier) {
            Long userId = authenticationService.nextUserId();

            authenticationService.saveIdentifier(userId, aIdentity.getIdentifierType(), mobile);

            aIdentity.setUserId(userId);
            authenticationService.saveUser(userId, aIdentity.getInvitationCode(), mobile);
        }
        else {
            aIdentity.setUserId(uIdentifier.getUserId());
        }
        List<String> permissionIdList = authenticationService.queryPermissionIdList(aIdentity.getUserId());
        return new AIdentityAuthenticationToken(aIdentity, permissionIdList);
    }

    @Override
    public AIdentity supports() {
        AIdentity aIdentity = new AIdentity();
        aIdentity.setIdentifierType(AIdentifierType.MOBILE.ordinal());
        aIdentity.setCredentialType(ACredentialType.VALID_CODE.ordinal());
        return aIdentity;
    }
}
