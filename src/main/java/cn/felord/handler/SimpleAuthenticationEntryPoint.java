package cn.felord.handler;


import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 处理认证失败的逻辑
 *
 * @author n1
 * @see AuthenticationException
 * @since 2021 /3/26 14:43
 */

public class SimpleAuthenticationEntryPoint extends ResponseWriter implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        String message = exceptionMessage(authException);
        request.setAttribute("exMsg", message);
        this.write(request, response);
    }

    @Override
    protected Map<String, Object> body(HttpServletRequest request) {
        Map<String, Object> map = new HashMap<>(3);
        String exMsg = (String) request.getAttribute("exMsg");
        map.put("code", HttpStatus.UNAUTHORIZED.value());
        map.put("uri", request.getRequestURI());
        map.put("message", exMsg);
        return map;
    }


    private String exceptionMessage(AuthenticationException exception) {
        String msg = "访问未授权";
        if (exception instanceof AccountExpiredException) {
            msg = "账户过期";
        } else if (exception instanceof AuthenticationCredentialsNotFoundException) {
            msg = "用户身份凭证未找到";
        } else if (exception instanceof AuthenticationServiceException) {
            msg = "用户身份认证服务异常";
        } else if (exception instanceof BadCredentialsException) {
            msg = exception.getMessage();
        }

        return msg;
    }


}
