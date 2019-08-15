package com.ddphin.security.token;

import com.ddphin.security.entity.AIdentity;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.stream.Collectors;

/**
 * AIdentityAuthenticationToken
 *
 * @Date 2019/7/17 下午2:15
 * @Author ddphin
 */
public class AIdentityAuthenticationToken extends AbstractAuthenticationToken {
    public AIdentityAuthenticationToken(AIdentity identity) {
        super(null);
        this.setAuthenticated(false);
        this.setDetails(identity);
    }
    public AIdentityAuthenticationToken(AIdentity identity, List<String> permissionIdList) {
        super(permissionIdList.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        this.setAuthenticated(true);
        this.setDetails(identity);
    }

    @Deprecated
    @Override
    public Object getCredentials() {
        return null;
    }

    @Deprecated
    @Override
    public Object getPrincipal() {
        return null;
    }
}
