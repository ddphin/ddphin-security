package com.ddphin.security.endpoint.entity;

/**
 * ClassName: APermission
 * Function:  APermission
 * Date:      2019/6/17 下午2:48
 * Author     ddphin
 * Version    V1.0
 */

public interface APermission {
    String getPermissionId();
    String getRequestUrl();
    String getRequestMethod();
}
