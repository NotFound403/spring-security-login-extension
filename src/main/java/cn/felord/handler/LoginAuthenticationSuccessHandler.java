package cn.felord.handler;

import cn.felord.jwt.JwtTokenGenerator;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * The type Login authentication success handler.
 *
 * @author n1
 * @since 2021 /3/27 11:27
 */

public class LoginAuthenticationSuccessHandler extends ResponseWriter implements AuthenticationSuccessHandler {
    private final JwtTokenGenerator jwtTokenGenerator;

    public LoginAuthenticationSuccessHandler(JwtTokenGenerator jwtTokenGenerator) {
        this.jwtTokenGenerator = jwtTokenGenerator;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        request.setAttribute("authentication", authentication);
        this.write(request, response);
    }

    @Override
    protected Map<String, Object> body(HttpServletRequest request) {
        Authentication authentication = (Authentication) request.getAttribute("authentication");
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        Map<String,Object> map = new HashMap<>(3);
        map.put("code", HttpStatus.OK.value());
        map.put("data",jwtTokenGenerator.tokenResponse(userDetails));
        map.put("message",HttpStatus.OK.getReasonPhrase());
        return map;
    }
}
