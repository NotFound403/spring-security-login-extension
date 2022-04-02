package cn.felord.security.config;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.SneakyThrows;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyStore;
import java.security.KeyStoreException;

/**
 * The Jwt configuration.
 *
 * @author n1
 */
@Configuration(proxyBeanMethods = false)
public class JwtConfiguration {
    private static final KeyStore JKS_STORE;


    static {
        try {
            JKS_STORE = KeyStore.getInstance("jks");
        } catch (KeyStoreException e) {
            throw new RuntimeException("can not obtain jks keystore instance");
        }
    }


    /**
     * 获取JWK (JSON Web Key)  包含了JOSE(可以认为是JWT的超集) 加密解密 签名验签的Key
     *
     * @return the jwk set
     */
    @Bean
    @ConditionalOnMissingBean
    @SneakyThrows
    public JWKSource<SecurityContext> jwkSource() {
        String path = "client.jks";
        String alias = "jose";
        String password = "felord.cn";

        ClassPathResource classPathResource = new ClassPathResource(path);
        char[] pin = password.toCharArray();
        JKS_STORE.load(classPathResource.getInputStream(), pin);

        RSAKey rsaKey = RSAKey.load(JKS_STORE, alias, pin);

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }


    /**
     * 用JWK来生成JWT的工具，底层使用了Nimbus库，这个库是Spring Security OAuth2 Client 默认引用的库
     *
     * @param jwkSource the jwk source
     * @return the jwt encoder
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

}