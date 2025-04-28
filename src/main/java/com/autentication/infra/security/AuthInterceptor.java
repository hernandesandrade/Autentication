package com.autentication.infra.security;

import com.autentication.exceptions.UserException;
import com.autentication.models.User;
import com.autentication.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

@Component
public class AuthInterceptor implements HandlerInterceptor {

    @Autowired
    private UserService userService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private SecurityFilter securityFilter;

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView mv) throws Exception {
        if (mv != null && mv.getViewName() != null && !mv.getViewName().startsWith("redirect:")) {
            checkAuth(mv, request);
        }
    }

    private void checkAuth(ModelAndView model, HttpServletRequest request) throws UserException {
        String token = securityFilter.extractTokenFromCookies(request);
        if (token != null) {
            String email = tokenService.validateToken(token);
            if (email != null) {
                User user = userService.getUserByEmail(email);
                    model.addObject("userName", user.getName().split(" ")[0]);
                    model.addObject("user", user);
                    model.addObject("role", user.getRole());
            }
        }
    }
}

