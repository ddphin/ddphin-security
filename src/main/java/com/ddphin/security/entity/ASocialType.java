package com.ddphin.security.entity;

/**
 * ASocialType
 *
 * @Date 2019/7/17 下午7:58
 * @Author ddphin
 */
public enum ASocialType {
    WX_APP_OPENID,
    WX_H5_OPENID,
    WX_XCX_OPENID,
    WX_SUB_OPENID,
    WX_SRV_OPENID,

    QQ_APP_OPENID,
    QQ_H5_OPENID;

    public static ASocialType fromCode(int code) {
        for (ASocialType t : values()) {
            if (t.ordinal() == code) {
                return t;
            }
        }
        return null;
    }
}
