package com.ddphin.security.decide;

import com.ddphin.security.entity.APemissionSecurityConfig;
import com.ddphin.security.endpoint.entity.APermission;
import com.ddphin.security.endpoint.service.AuthenticationService;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.List;

/**
 * APermissionFilterInvocationSecurityMetadataSource
 *
 * @author ddphin
 */
public class APermissionFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
    private FilterInvocationSecurityMetadataSource  superMetadataSource;
    private AuthenticationService authenticationService;

    public APermissionFilterInvocationSecurityMetadataSource(
            FilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource,
            AuthenticationService authenticationService) {
        this.superMetadataSource = filterInvocationSecurityMetadataSource;
        this.authenticationService = authenticationService;
    }

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        HttpServletRequest request = ((FilterInvocation) object).getRequest();

        List<? extends APermission> allPermission = authenticationService.queryAllPermission();
        if (null != allPermission) {
            for (APermission p : allPermission) {
                RequestMatcher matcher = new AntPathRequestMatcher(p.getRequestUrl(), p.getRequestMethod());
                if (matcher.matches(request)) {
                    return APemissionSecurityConfig.createList(p.getPermissionId());
                }
            }
        }

        //  返回代码定义的默认配置
        return superMetadataSource.getAttributes(object);
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}
