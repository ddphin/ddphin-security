package com.ddphin.security.endpoint.entity;

/**
 * ClassName: AIdentifier
 * Function:  AIdentifier
 * Date:      2019/6/17 下午2:48
 * Author     ddphin
 * Version    V1.0
 */

public interface AIdentifier {
    Long getUserId();
    Integer getIdentifierType();
    String getIdentifierValue();
}
