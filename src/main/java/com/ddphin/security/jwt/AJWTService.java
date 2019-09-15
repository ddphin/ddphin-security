package com.ddphin.security.jwt;

import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * AJWTService
 *
 * @Date 2019/7/18 下午5:28
 * @Author ddphin
 */
public interface AJWTService {
    String create();
    String refresh();
    void remove(String token);

    DecodedJWT validate(String token, String ip);

    default void onSuccess() {}
}
