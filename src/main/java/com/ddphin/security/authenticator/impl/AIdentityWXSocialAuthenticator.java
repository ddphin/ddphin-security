package com.ddphin.security.authenticator.impl;

import com.ddphin.security.authenticator.AIdentityAuthenticator;
import com.ddphin.security.entity.ACredentialType;
import com.ddphin.security.entity.AIdentity;
import com.ddphin.security.entity.AIdentifierType;

/**
 * AIdentityWXAppSocialAuthenticator
 *
 * @Date 2019/7/17 下午8:36
 * @Author ddphin
 */
public class AIdentityWXSocialAuthenticator extends AIdentityAbstractSocialAuthenticator implements AIdentityAuthenticator {

    @Override
    public AIdentity supports() {
        AIdentity aIdentity = new AIdentity();
        aIdentity.setIdentifierType(AIdentifierType.WX.ordinal());
        aIdentity.setCredentialType(ACredentialType.GRANT_CODE.ordinal());
        return aIdentity;
    }
}
