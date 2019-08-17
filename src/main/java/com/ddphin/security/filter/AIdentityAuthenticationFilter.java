package com.ddphin.security.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.ddphin.security.entity.AIdentity;
import com.ddphin.security.token.AIdentityAuthenticationToken;
import com.ddphin.security.util.RequestHelper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * AIdentityAuthenticationFilter
 *
 * @Date 2019/7/17 下午2:09
 * @Author ddphin
 */
public class AIdentityAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public AIdentityAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        String body = StreamUtils.copyToString(httpServletRequest.getInputStream(), StandardCharsets.UTF_8);
        AIdentity identity = new AIdentity();
        if(StringUtils.hasText(body)) {
            JSONObject jsonObj = JSON.parseObject(body);
            Integer identifierType = jsonObj.getInteger("identifierType");
            String identifierValue = jsonObj.getString("identifierValue");
            Integer credentialType = jsonObj.getInteger("credentialType");
            String credentialValue = jsonObj.getString("credentialValue");
            JSONObject data = jsonObj.getJSONObject("data");
            String invitationCode = jsonObj.getString("invitationCode");
            String ip = RequestHelper.getIp(httpServletRequest);

            Assert.notNull(identifierType, "identifierType is required");
            Assert.notNull(identifierValue, "identifierValue is required");
            Assert.notNull(identifierType, "identifierType is required");
            Assert.notNull(credentialValue, "credentialValue is required");

            identity.setIdentifierType(identifierType);
            identity.setIdentifierValue(identifierValue);

            identity.setCredentialType(credentialType);
            identity.setCredentialValue(credentialValue);

            identity.setData(data);
            identity.setInvitationCode(invitationCode);
            identity.setIp(ip);
        }
        //封装到token中提交
        AIdentityAuthenticationToken authRequest = new AIdentityAuthenticationToken(identity);

        return this.getAuthenticationManager().authenticate(authRequest);
    }
}
