package com.ddphin.security.entity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * AGrantedAuthority
 *
 * @Date 2019/8/23 下午9:56
 * @Author ddphin
 */
public class AGrantedAuthority implements GrantedAuthority {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final String permission;

    public AGrantedAuthority(String permission) {
        Assert.hasText(permission, "A granted authority textual representation is required");
        this.permission = permission;
    }

    @Override
    public String getAuthority() {
        return permission;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj instanceof AGrantedAuthority) {
            return permission.equals(((AGrantedAuthority) obj).permission);
        }

        return false;
    }

    @Override
    public int hashCode() {
        return this.permission.hashCode();
    }

    @Override
    public String toString() {
        return this.permission;
    }
}
