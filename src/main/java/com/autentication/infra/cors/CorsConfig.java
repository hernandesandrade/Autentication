package com.autentication.infra.cors;

import com.autentication.infra.security.AuthInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.math.BigDecimal;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Locale;

@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Autowired
    private AuthInterceptor authInterceptor;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:8080")
                .allowedMethods("GET", "POST", "DELETE", "PUT");
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authInterceptor)
                .addPathPatterns("/**"); // Aplica a todas as URLs
    }

    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(String.class, BigDecimal.class, source -> {
            if (source.trim().isEmpty()) {
                return null;
            }
            try {
                DecimalFormatSymbols symbols = new DecimalFormatSymbols(new Locale("pt", "BR"));
                DecimalFormat decimalFormat = new DecimalFormat("#,##0.00", symbols);
                decimalFormat.setParseBigDecimal(true);
                return (BigDecimal) decimalFormat.parse(source);
            } catch (Exception e) {
                throw new IllegalArgumentException("Formato de número inválido: " + source, e);
            }
        });
    }

}