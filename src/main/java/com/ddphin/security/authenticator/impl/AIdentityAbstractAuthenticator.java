package com.ddphin.security.authenticator.impl;

import com.ddphin.security.authenticator.AIdentityAuthenticator;
import com.ddphin.security.endpoint.entity.AIdentifier;
import com.ddphin.security.endpoint.entity.ASocial;
import com.ddphin.security.endpoint.entity.ASocialDetail;
import com.ddphin.security.endpoint.service.AuthenticationService;
import com.ddphin.security.entity.AIdentity;
import com.ddphin.security.social.ASocialProvider;
import com.ddphin.security.social.ASocialProviderHolder;
import com.ddphin.security.token.AIdentityAuthenticationToken;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.util.List;

/**
 * AIdentityAbstractSocialAuthenticator
 *
 * @Date 2019/7/17 下午8:36
 * @Author ddphin
 */
public abstract class AIdentityAbstractAuthenticator implements AIdentityAuthenticator {
    public abstract Authentication doAuthentication(
            Authentication authentication,
            AuthenticationService authenticationService
    ) throws AuthenticationException;


    @Override
    public Authentication authenticate(
            Authentication authentication,
            AuthenticationService authenticationService,
            DataSourceTransactionManager dataSourceTransactionManager) throws AuthenticationException {
        DefaultTransactionDefinition def = new DefaultTransactionDefinition();
        // 事物隔离级别，开启新事务，这样会比较安全些
        def.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        // 获得事务状态
        TransactionStatus status = dataSourceTransactionManager.getTransaction(def);

        try {
            Authentication authenticated = this.doAuthentication(authentication, authenticationService);
            dataSourceTransactionManager.commit(status);
            return authenticated;
        }
        catch (Exception e) {
            dataSourceTransactionManager.rollback(status);
            throw new BadCredentialsException("Authentication Failed");
        }
    }
}
