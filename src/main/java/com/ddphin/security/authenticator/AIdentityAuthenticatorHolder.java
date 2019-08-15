package com.ddphin.security.authenticator;

import com.ddphin.security.authenticator.impl.AIdentityMobilePasswordAuthenticator;
import com.ddphin.security.authenticator.impl.AIdentityMobileValidCodeAuthenticator;
import com.ddphin.security.authenticator.impl.AIdentityQQSocialAuthenticator;
import com.ddphin.security.authenticator.impl.AIdentityWXSocialAuthenticator;
import com.ddphin.security.entity.AIdentity;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * AIdentityAuthenticatorHolder
 *
 * @Date 2019/7/17 下午3:08
 * @Author ddphin
 */
public class AIdentityAuthenticatorHolder {

    private static final Map<String, AIdentityAuthenticator> map = Stream.of(
            new AIdentityMobilePasswordAuthenticator(),
            new AIdentityMobileValidCodeAuthenticator(),
            new AIdentityQQSocialAuthenticator(),
            new AIdentityWXSocialAuthenticator())
            .collect(Collectors.toMap(o -> o.supports().getIdentityAuthenticatorType(), o -> o));

    public static AIdentityAuthenticator get(AIdentity identity) {
        return map.get(identity.getIdentityAuthenticatorType());
    }
}
