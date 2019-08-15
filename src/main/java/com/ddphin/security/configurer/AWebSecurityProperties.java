package com.ddphin.security.configurer;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Arrays;

/**
 * AWebSecurityProperties
 *
 * @Date 2019/8/15 下午8:08
 * @Author ddphin
 */
@Data
@ConfigurationProperties(prefix = "spring.security.authorize")
public class AWebSecurityProperties {
    private String logout;
    private String login;
    private String[] permissive;

    public String[] getPermissive() {
        if (null != this.permissive && 0 < this.permissive.length) {
            String[] permissive = Arrays.copyOf(this.permissive, this.permissive.length + 2);
            permissive[this.permissive.length] = logout;
            permissive[this.permissive.length + 1] = login;
            return permissive;
        }
        else {
            return new String[] {
                    login,
                    logout
            };
        }
    }

}
