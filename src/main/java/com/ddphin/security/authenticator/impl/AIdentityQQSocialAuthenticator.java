package com.ddphin.security.authenticator.impl;

import com.ddphin.security.authenticator.AIdentityAuthenticator;
import com.ddphin.security.entity.ACredentialType;
import com.ddphin.security.entity.AIdentity;
import com.ddphin.security.entity.AIdentifierType;

/**
 * AIdentityQQAppSocialAuthenticator
 *
 * @Date 2019/7/17 下午8:36
 * @Author ddphin
 */
public class AIdentityQQSocialAuthenticator extends AIdentityAbstractSocialAuthenticator implements AIdentityAuthenticator {

    @Override
    public AIdentity supports() {
        AIdentity aIdentity = new AIdentity();
        aIdentity.setIdentifierType(AIdentifierType.QQ.ordinal());
        aIdentity.setCredentialType(ACredentialType.GRANT_CODE.ordinal());
        return aIdentity;
    }
}
