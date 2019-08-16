package com.ddphin.security.provider;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.ddphin.security.jwt.AJWTService;
import com.ddphin.security.token.AJwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * AJwtAuthenticationProvider
 *
 * @Date 2019/7/17 下午3:08
 * @Author ddphin
 */
public class AJwtAuthenticationProvider implements AuthenticationProvider {

    private AJWTService jwtService;

    public AJwtAuthenticationProvider(AJWTService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AJwtAuthenticationToken jwtToken = (AJwtAuthenticationToken) authentication;
        String token = (String) jwtToken.getDetails();
        DecodedJWT jwt = jwtService.validate(token, jwtToken.getIp());
        AJwtAuthenticationToken authenticationToken = new AJwtAuthenticationToken(jwt, jwtToken.getIp());
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return AJwtAuthenticationToken.class.isAssignableFrom(aClass);
    }
}
