package com.ddphin.security.entity;

/**
 * ACredentialType
 *
 * @Date 2019/7/17 下午7:58
 * @Author ddphin
 */
public enum ACredentialType {
    PASSWORD,
    VALID_CODE,
    GRANT_CODE,
    ;

    public static ACredentialType fromCode(int code) {
        for (ACredentialType t : values()) {
            if (t.ordinal() == code) {
                return t;
            }
        }
        return null;
    }
}
