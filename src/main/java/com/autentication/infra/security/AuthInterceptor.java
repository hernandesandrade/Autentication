package com.autentication.infra.security;

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

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView mv) throws Exception {
//        User user = userService.getUser(request);
//        if (user != null && mv != null) {
//            addUserName(user, mv);
//        }
    }

//    private void addUserName(User user, ModelAndView mv){
//        mv.addObject("userName", user.getName().split(" ")[0]);
//    }
}

