package com.ddphin.security.endpoint.social;

import com.ddphin.security.social.ASocialProvider;
import com.ddphin.security.social.ASocialProviderHolder;

import javax.annotation.PostConstruct;

/**
 * ASocialProviderRegister
 *
 * @Date 2019/7/20 下午5:38
 * @Author ddphin
 */
public abstract class ASocialProviderRegister implements ASocialProvider {
    @PostConstruct
    public void register() {
        ASocialProviderHolder.add(this);
    }
}
