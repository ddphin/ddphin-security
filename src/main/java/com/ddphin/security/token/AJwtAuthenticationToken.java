package com.ddphin.security.token;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.ddphin.security.entity.AIdentity;
import com.ddphin.security.entity.AIdentifierType;
import com.ddphin.security.entity.ASocialType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.stream.Collectors;

/**
 * AJwtAuthenticationToken
 *
 * @Date 2019/7/17 下午2:15
 * @Author ddphin
 */
public class AJwtAuthenticationToken extends AbstractAuthenticationToken {
    private String ip;

    public AJwtAuthenticationToken(String jwt, String ip) {
        super(null);
        this.setAuthenticated(false);
        this.setDetails(jwt);
        this.ip = ip;
    }
    public AJwtAuthenticationToken(DecodedJWT jwt, String ip) {
        super(jwt.getClaim("Authority").asList(String.class).stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        this.setAuthenticated(true);

        List<String> audiences = jwt.getAudience();
        Long userId = Long.valueOf(jwt.getSubject());
        String identifierType = audiences.get(0);

        AIdentity identity = new AIdentity();
        identity.setIp(ip);
        identity.setUserId(userId);
        identity.setIdentifierType(AIdentifierType.valueOf(identifierType).ordinal());
        if (1 < audiences.size()) {
            String socialType = audiences.get(1);
            identity.setSocialType(ASocialType.valueOf(socialType).ordinal());
        }
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

    public String getIp() {
        return this.ip;
    }
}
