package com.ddphin.security.endpoint.entity;

/**
 * ClassName: ACredential
 * Function:  ACredential
 * Date:      2019/6/17 下午2:48
 * Author     ddphin
 * Version    V1.0
 */

public interface ACredential {
    Long getUserId();
    Integer getCredentialType();
    String getCredentialValue();
}
