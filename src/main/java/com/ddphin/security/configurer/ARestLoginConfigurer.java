package com.ddphin.security.configurer;

import com.ddphin.security.filter.AIdentityAuthenticationFilter;
import com.ddphin.security.handler.AIdentityAuthenticationFailureHandler;
import com.ddphin.security.handler.AIdentityAuthenticationSuccessHandler;
import com.ddphin.security.endpoint.service.AJWTService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * ARestLoginConfigurer
 *
 * @Date 2019/7/18 下午8:37
 * @Author ddphin
 */
public class ARestLoginConfigurer<T extends ARestLoginConfigurer<T, B>, B extends HttpSecurityBuilder<B>> extends AbstractHttpConfigurer<T, B> {
    private AIdentityAuthenticationFilter authFilter;
    private AJWTService jwtService;

    public ARestLoginConfigurer(AJWTService jwtService, String url) {
        this.authFilter = new AIdentityAuthenticationFilter(new AntPathRequestMatcher(url, "POST"));
        this.jwtService = jwtService;
    }

    @Override
    public void configure(B http) {
        authFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        authFilter.setAuthenticationFailureHandler(new AIdentityAuthenticationFailureHandler());
        authFilter.setAuthenticationSuccessHandler(new AIdentityAuthenticationSuccessHandler(jwtService));
        authFilter.setSessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy());

        AIdentityAuthenticationFilter filter = this.postProcess(authFilter);
        http.addFilterAfter(filter, LogoutFilter.class);
    }
}
