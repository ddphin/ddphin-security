package com.ddphin.security.decide;

import com.ddphin.security.entity.AGrantedAuthority;
import com.ddphin.security.entity.APemissionSecurityConfig;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.stream.Collectors;

/**
 * APermissionBasedVoter
 *
 * @Date 2019/8/14 下午7:28
 * @Author ddphin
 */
public class APermissionBasedVoter implements AccessDecisionVoter<Object> {
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof APemissionSecurityConfig;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        if (CollectionUtils.isEmpty(attributes)) {
            return ACCESS_GRANTED;
        }
        if (null == authentication) {
            return ACCESS_DENIED;
        }

        Collection<ConfigAttribute> needAuthorities =
                attributes.stream().filter(this::supports).collect(Collectors.toList());

        if (CollectionUtils.isEmpty(needAuthorities)) {
            return ACCESS_GRANTED;
        }

        if (CollectionUtils.isEmpty(authentication.getAuthorities())) {
            return ACCESS_DENIED;
        }

        Collection<? extends GrantedAuthority> hasAuthorities =
                authentication.getAuthorities().stream().filter(
                        o -> o instanceof AGrantedAuthority).collect(Collectors.toList());

        if (CollectionUtils.isEmpty(hasAuthorities)) {
            return ACCESS_DENIED;
        }

        if (attributes.stream().allMatch(o ->
                hasAuthorities.stream().anyMatch(t ->
                        t.getAuthority().equals(o.getAttribute())))) {
            return ACCESS_GRANTED;
        }

        return ACCESS_DENIED;
    }
}
