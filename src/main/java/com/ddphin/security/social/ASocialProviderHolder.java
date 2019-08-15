package com.ddphin.security.social;

import com.ddphin.security.entity.ASocialType;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ASocialProviderHolder
 *
 * @Date 2019/7/21 下午8:04
 * @Author ddphin
 */
public class ASocialProviderHolder {
    private static final Map<ASocialType, ASocialProvider> map = new ConcurrentHashMap<>();

    public static ASocialProvider get(ASocialType type) {
        return map.get(type);
    }
    public static void add(ASocialProvider provider) {
        map.put(provider.socialType(), provider);
    }
}
