package com.ddphin.security.entity;

/**
 * AIdentifierType
 *
 * @Date 2019/7/17 下午7:58
 * @Author ddphin
 */
public enum AIdentifierType {
    MOBILE,
    WX,
    QQ;

    public static AIdentifierType fromCode(int code) {
        for (AIdentifierType t : values()) {
            if (t.ordinal() == code) {
                return t;
            }
        }
        return null;
    }
}
