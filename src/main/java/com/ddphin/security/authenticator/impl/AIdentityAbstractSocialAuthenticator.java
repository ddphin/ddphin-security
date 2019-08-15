package com.ddphin.security.authenticator.impl;

import com.ddphin.security.endpoint.service.AuthenticationService;
import com.ddphin.security.authenticator.AIdentityAuthenticator;
import com.ddphin.security.endpoint.entity.AIdentifier;
import com.ddphin.security.entity.AIdentity;
import com.ddphin.security.endpoint.entity.ASocial;
import com.ddphin.security.social.ASocialProviderHolder;
import com.ddphin.security.endpoint.entity.ASocialDetail;
import com.ddphin.security.social.ASocialProvider;
import com.ddphin.security.token.AIdentityAuthenticationToken;
import com.ddphin.security.entity.ASocialType;
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

        ASocialProvider socialProvider = ASocialProviderHolder.get(ASocialType.fromCode(aIdentity.getSocialType()));
        ASocialDetail socialInfo = socialProvider.querySocialDetail(aIdentity.getCredentialValue(), aIdentity.getSocialExtra());
        if (null == socialInfo || null == socialInfo.getUnionid() || null == socialInfo.getOpenid()) {
            throw new BadCredentialsException("Authentication Failed");
        }
        aIdentity.setIdentifierValue(socialInfo.getUnionid());
        aIdentity.setSocialValue(socialInfo.getOpenid());
        AIdentifier uIdentifier =  authenticationService.queryIdentifier(aIdentity.getIdentifierType(), socialInfo.getUnionid());

        if (null == uIdentifier) {
            Long userId = authenticationService.nextUserId();
            aIdentity.setUserId(userId);

            authenticationService.saveIdentifier(userId, aIdentity.getIdentifierType(), aIdentity.getIdentifierValue());

            authenticationService.saveUser(userId,  aIdentity.getInvitationCode(), socialInfo);
        }
        else if (!uIdentifier.getIdentifierValue().equals(aIdentity.getIdentifierValue())) {
            throw new BadCredentialsException("Authentication Failed");
        }
        else {
            aIdentity.setUserId(uIdentifier.getUserId());
        }

        ASocial social = authenticationService.querySocial(aIdentity.getUserId(), aIdentity.getIdentifierType(), aIdentity.getSocialType());
        if (null == social) {
            authenticationService.saveSocial(aIdentity.getUserId(), aIdentity.getIdentifierType(), aIdentity.getSocialType(), socialInfo);
        }
        else if (!social.getSocialValue().equals(aIdentity.getSocialValue())) {
            throw new BadCredentialsException("Authentication Failed");
        }
        else {
            authenticationService.updateSocial(aIdentity.getUserId(), aIdentity.getIdentifierType(), aIdentity.getSocialType(), socialInfo);
        }

        List<String> permissionIdList = authenticationService.queryPermissionIdList(aIdentity.getUserId());
        return new AIdentityAuthenticationToken(aIdentity, permissionIdList);
    }
}
