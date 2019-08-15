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
    AIdentifier queryIdentifier(Integer identifierType, String identifierValue);

    ACredential queryCredential(Long userId, Integer credentialType);

    List<String> queryPermissionIdList(Long userId);
    List<? extends APermission> queryAllPermission();

    String queryValidCode(String mobile);

    Long nextUserId();

    void saveUser(Long userId, String invitationCode, String mobile);
    void saveUser(Long userId, String invitationCode, ASocialDetail socialInfo);

    void saveIdentifier(Long userId, Integer identifierType, String identifierValue);

    ASocial querySocial(Long userId, Integer identifierType, Integer socialType);

    void saveSocial(Long userId, Integer identifierType, Integer socialType, ASocialDetail socialInfo);

    void updateSocial(Long userId, Integer identifierType, Integer socialType, ASocialDetail socialInfo);
}
