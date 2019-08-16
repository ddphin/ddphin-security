package com.ddphin.security.endpoint.service;

import com.ddphin.security.endpoint.entity.*;

import java.util.List;

/**
 * AuthenticationService
 *
 * @Date 2019/8/14 下午2:57
 * @Author ddphin
 */
public interface AuthenticationService {
    // Identifier
    AIdentifier queryIdentifier(Integer identifierType, String identifierValue);
    void saveIdentifier(Long userId, Integer identifierType, String identifierValue);

    // Credential
    ACredential queryCredential(Long userId, Integer credentialType);

    // Permission
    List<String> queryPermissionIdList(Long userId);
    List<? extends APermission> queryAllPermission();

    // ValidCode
    String queryValidCode(String mobile);
    void removeValidCode(String mobile);

    // User
    Long nextUserId();
    void saveUser(Long userId, String invitationCode, String mobile);
    void saveUser(Long userId, String invitationCode, ASocialDetail socialInfo);

    // Social
    ASocial querySocial(Long userId, Integer identifierType, Integer socialType);
    void saveSocial(Long userId, Integer identifierType, Integer socialType, ASocialDetail socialDetail);
    void updateSocial(Long userId, Integer identifierType, Integer socialType, ASocialDetail socialDetail);
}
