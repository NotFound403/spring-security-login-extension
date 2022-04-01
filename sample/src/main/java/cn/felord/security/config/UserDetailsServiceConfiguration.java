package cn.felord.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author felord.cn
 * @since 1.0.0
 */
@Configuration(proxyBeanMethods = false)
public class UserDetailsServiceConfiguration {

    @Bean
    UserDetailsService userDetailsService() {

        return username ->
                // 用户名
                User.withUsername(username)
                        // 密码
                        .password("password")
                        // 权限集
                        .authorities("ROLE_USER", "ROLE_ADMIN")
                        .build();
    }

}
