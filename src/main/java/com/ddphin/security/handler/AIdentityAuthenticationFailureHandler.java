package com.ddphin.security.handler;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * AIdentityAuthenticationFailureHandler
 *
 * @Date 2019/7/17 下午3:08
 * @Author ddphin
 */
public class AIdentityAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) {
        httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
    }
}
