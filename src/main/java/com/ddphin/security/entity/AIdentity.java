package com.ddphin.security.entity;

import lombok.Data;

import java.util.Map;

/**
 * AIdentity
 *
 * @Date 2019/7/17 上午10:32
 * @Author ddphin
 */
@Data
public class AIdentity {
    private Long userId;

    private Integer identifierType;
    private String identifierValue;


    private Integer credentialType;
    private String credentialValue;

    private Map<String, Object> data;

    private String invitationCode;
    private String ip;

    public String getIdentityAuthenticatorType() {
        return String.format("_it_=%s@_ct_=%s", identifierType, credentialType);
    }
}
