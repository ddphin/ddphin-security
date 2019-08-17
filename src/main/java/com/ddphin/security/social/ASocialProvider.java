package com.ddphin.security.social;

import com.ddphin.security.endpoint.entity.ASocialDetail;

import java.util.Map;

/**
 * ASocialProvider
 *
 * @Date 2019/7/20 下午5:38
 * @Author ddphin
 */
public interface ASocialProvider {
    Integer socialType();
    ASocialDetail querySocialDetail(String code, Map<String, Object> socialExtra);
}
