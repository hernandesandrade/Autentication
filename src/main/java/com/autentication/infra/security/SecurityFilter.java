package com.autentication.infra.security;

import com.autentication.dto.UserDTO;
import com.autentication.models.User;
import com.autentication.repositories.UserRepository;
import com.autentication.services.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    TokenService tokenService;

    @Autowired
    UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = extractTokenFromCookies(request);
        if (token != null) {
            String email = tokenService.validateToken(token);
            if (email != null) {
                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    Optional<User> userOptional = userRepository.findByEmail(email);
                    if (userOptional.isPresent()) {
                        User user = userOptional.get();
                        request.getSession().setAttribute("userLogado", new UserDTO(user.getName(), user.getEmail(), user.isAtivo()));
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                user.getEmail(),
                                null,
                                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole())) // Adicione roles/authorities aqui, se necessário
                        );
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }

                }
            }else{
                Object sessionUser = request.getSession().getAttribute("userLogado");
                if (sessionUser != null){
                    request.getSession().removeAttribute("userLogado");
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    public String extractTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("auth_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

}