package cn.felord.security.config;

import cn.felord.configuers.authentication.LoginFilterSecurityConfigurer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The type Web security configuration.
 *
 * @author n1
 */
@EnableWebSecurity(debug = true)
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class WebSecurityConfiguration {
    /**
     * Default security filter chain security filter chain.
     *
     * @param http the http
     * @return the security filter chain
     * @throws Exception the exception
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {


        http.csrf().disable()
                .authorizeRequests()
                .mvcMatchers("/foo/**").access("hasAuthority('ROLE_USER')")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .apply(new LoginFilterSecurityConfigurer<>())
                .captchaLogin(captchaLoginConfigurer->{

                })
                .miniAppLogin(miniAppLoginConfigurer->{

                });


        return http.build();
    }
}
