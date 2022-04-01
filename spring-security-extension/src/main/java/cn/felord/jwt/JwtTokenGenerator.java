package cn.felord.jwt;


import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;


/**
 * jwt token  generator
 *
 * @author n1
 * @since 2021 /3/27 13:33
 */

public interface JwtTokenGenerator {

    OAuth2AccessTokenResponse tokenResponse(UserDetails userDetails);

}
