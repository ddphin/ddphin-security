package com.ddphin.security.handler;

import com.ddphin.security.endpoint.service.AJWTService;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * AIdentityAuthenticationSuccessHandler
 *
 * @Date 2019/7/17 下午3:08
 * @Author ddphin
 */
public class AIdentityAuthenticationSuccessHandler
        implements AuthenticationSuccessHandler {
    private AJWTService jwtService;

    public AIdentityAuthenticationSuccessHandler(AJWTService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String token = jwtService.create();
        response.setHeader("Authorization", "Bearer " + token);
    }
}
