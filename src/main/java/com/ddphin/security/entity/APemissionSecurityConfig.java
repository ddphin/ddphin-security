package com.ddphin.security.entity;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;

/**
 * APemissionSecurityConfig
 *
 * @Date 2019/8/15 上午10:09
 * @Author ddphin
 */
public class APemissionSecurityConfig extends SecurityConfig {
    public APemissionSecurityConfig(String config) {
        super(config);
    }

    public static List<ConfigAttribute> createList(String... attributeNames) {
        Assert.notNull(attributeNames, "You must supply an array of attribute names");
        List<ConfigAttribute> attributes = new ArrayList<>(
                attributeNames.length);

        for (String attribute : attributeNames) {
            attributes.add(new APemissionSecurityConfig(attribute.trim()));
        }

        return attributes;
    }
}
