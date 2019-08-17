package com.ddphin.security.authenticator.impl;

import com.ddphin.security.authenticator.AIdentityAuthenticator;
import com.ddphin.security.endpoint.entity.AIdentifier;
import com.ddphin.security.endpoint.entity.ASocial;
import com.ddphin.security.endpoint.entity.ASocialDetail;
import com.ddphin.security.endpoint.service.AuthenticationService;
import com.ddphin.security.entity.AIdentity;
import com.ddphin.security.social.ASocialProvider;
import com.ddphin.security.social.ASocialProviderHolder;
import com.ddphin.security.token.AIdentityAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * AIdentityAbstractSocialAuthenticator
 *
 * @Date 2019/7/17 下午8:36
 * @Author ddphin
 */
public abstract class AIdentityAbstractSocialAuthenticator implements AIdentityAuthenticator {
    @Transactional(propagation = Propagation.REQUIRED, rollbackFor=Exception.class)
    @Override
    public Authentication authenticate(
            Authentication authentication,
            AuthenticationService authenticationService) throws AuthenticationException {
        AIdentity aIdentity = (AIdentity) authentication.getDetails();

        int socialType = Integer.parseInt(aIdentity.getIdentifierValue());
        ASocialProvider socialProvider = ASocialProviderHolder.get(socialType);
        ASocialDetail socialInfo = socialProvider.querySocialDetail(aIdentity.getCredentialValue(), aIdentity.getData());
        if (null == socialInfo || null == socialInfo.getUnionid() || null == socialInfo.getOpenid()) {
            throw new BadCredentialsException("Authentication Failed");
        }

        AIdentifier uIdentifier =  authenticationService.queryIdentifier(aIdentity.getIdentifierType(), socialInfo.getUnionid());

        if (null == uIdentifier) {
            Long userId = authenticationService.nextUserId();
            aIdentity.setUserId(userId);

            authenticationService.saveIdentifier(userId, aIdentity.getIdentifierType(), socialInfo.getUnionid());

            authenticationService.saveUser(userId,  aIdentity.getInvitationCode(), socialInfo);
        }
        else {
            aIdentity.setUserId(uIdentifier.getUserId());
        }

        ASocial social = authenticationService.querySocial(aIdentity.getUserId(), aIdentity.getIdentifierType(), socialType);
        if (null == social) {
            authenticationService.saveSocial(aIdentity.getUserId(), aIdentity.getIdentifierType(), socialType, socialInfo);
        }
        else {
            authenticationService.updateSocial(aIdentity.getUserId(), aIdentity.getIdentifierType(), socialType, socialInfo);
        }

        List<String> permissionIdList = authenticationService.queryPermissionIdList(aIdentity.getUserId());
        return new AIdentityAuthenticationToken(aIdentity, permissionIdList);
    }
}
