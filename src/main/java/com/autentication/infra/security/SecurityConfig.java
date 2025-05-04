package com.autentication.infra.security;

import com.autentication.google.OAuth2SuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    SecurityFilter securityFilter;

    @Autowired
    private OAuth2SuccessHandler oAuth2SuccessHandler;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                //desativar "CSRF protection" se esse sistema for uma api ".csrf(AbstractHttpConfigurer::disable)"
                //ativar se for um projeto unico com thymeleaf (basta excluir)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // Permite sessões para formLogin
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/erro" ,"/login", "/cadastrar", "/publico", "/confirmar-email", "/forgot-password", "/reset-password", "/reset-password-error").permitAll()
                        .requestMatchers("/privado", "/privado2").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(oAuth2SuccessHandler) // aqui entra o handler personalizado
                )
                .logout(logout -> logout
                        .logoutUrl("/logout") // URL para fazer logout
                        .logoutSuccessUrl("/") // Redireciona após logout
                        .invalidateHttpSession(true) // Invalida a sessão
                        .deleteCookies("auth_token") // Deleta o cookie do token
                        .permitAll()
                )
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")) // Redireciona para /login
                )
//                .requestCache(requestCacheConfigurer -> requestCacheConfigurer
//                        .requestCache(new HttpSessionRequestCache() {
//                            @Override
//                            public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
//                                // Ignorar solicitações para favicon.ico
//                                if (!request.getRequestURI().contains("favicon.ico")) {
//                                    super.saveRequest(request, response);
//                                }
//                            }
//                        })
//                )
//                .formLogin(form -> form
//                        .loginPage("/login")
//                        .defaultSuccessUrl("/", true)
//                        // Redireciona usuários logados que tentam acessar /login
//                        .successHandler((request, response, authentication) -> {
//                            if (authentication != null && authentication.isAuthenticated()) {
//                                response.sendRedirect("/");
//                            }
//                        })
//                )
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class);


        // Não adicione a configuração formLogin aqui
        return http.build();
    }

    @Bean
    public HttpSessionRequestCache requestCache() {
        return new HttpSessionRequestCache();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder();

    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}



