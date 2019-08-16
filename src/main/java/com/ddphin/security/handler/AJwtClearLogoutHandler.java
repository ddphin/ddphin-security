package com.ddphin.security.handler;

import com.ddphin.security.jwt.AJWTService;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * AJwtClearLogoutHandler
 *
 * @Date 2019/7/21 下午3:19
 * @Author ddphin
 */
public class AJwtClearLogoutHandler implements LogoutHandler {
    private AJWTService jwtService;

    public AJwtClearLogoutHandler(AJWTService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = request.getHeader("Authorization");
        token = token.replaceFirst("Bearer ", "");
        jwtService.remove(token);
    }
}
