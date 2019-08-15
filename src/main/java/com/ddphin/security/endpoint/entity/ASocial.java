package com.ddphin.security.endpoint.entity;

/**
 * ClassName: ASocial
 * Function:  ASocial
 * Date:      2019/6/17 下午2:48
 * Author     ddphin
 * Version    V1.0
 */

public interface ASocial {
    Long getUserId();
    Integer getIdentifierType();
    Integer getSocialType();
    String getSocialValue();
}
