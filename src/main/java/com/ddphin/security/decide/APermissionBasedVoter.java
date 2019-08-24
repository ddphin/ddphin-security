package com.ddphin.security.decide;

import com.ddphin.security.entity.AGrantedAuthority;
import com.ddphin.security.entity.APemissionSecurityConfig;
import com.ddphin.security.token.AIdentityAuthenticationToken;
import com.ddphin.security.token.AJwtAuthenticationToken;
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

    private boolean supports(Authentication authentication) {
        return authentication instanceof AJwtAuthenticationToken;
    }
    private Collection<ConfigAttribute> getRequiredAuthorities(Collection<ConfigAttribute> attributes) {
        return CollectionUtils.isEmpty(attributes) ? attributes :
                attributes.stream().filter(this::supports).collect(Collectors.toList());
    }
    private boolean hasRequiredAuthorities(Authentication authentication, Collection<ConfigAttribute> attributes) {
        return !CollectionUtils.isEmpty(authentication.getAuthorities()) &&
                attributes.stream().allMatch(o ->
                        authentication.getAuthorities().stream().anyMatch(t ->
                                t.getAuthority().equals(o.getAttribute())));
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        Collection<ConfigAttribute> requiredAuthorities = this.getRequiredAuthorities(attributes);

        if (CollectionUtils.isEmpty(requiredAuthorities)) {
            return ACCESS_GRANTED;
        }
        else if(!this.supports(authentication)) {
            return ACCESS_DENIED;
        }
        else if (this.hasRequiredAuthorities(authentication, requiredAuthorities)) {
            return ACCESS_GRANTED;
        }
        else {
            return ACCESS_DENIED;
        }
    }
}
