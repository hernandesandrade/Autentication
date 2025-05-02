package com.autentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class AutenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AutenticationApplication.class, args);
	}

}
