package com.csrfshield;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * CSRF Shield - Web Application Security System
 *
 * Entry point. Run with:  mvn spring-boot:run
 * Then open:              http://localhost:8080/login
 */
@SpringBootApplication
public class CsrfShieldApplication {
    public static void main(String[] args) {
        SpringApplication.run(CsrfShieldApplication.class, args);
    }
}
