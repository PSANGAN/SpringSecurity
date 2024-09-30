package com.pcgs.spring.securitypoc.config;

import com.pcgs.spring.securitypoc.exceptionhandling.CustomAccessDeniedHandler;
import com.pcgs.spring.securitypoc.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("prod")
public class ProjectSecurityProdConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // Invalid Session URL Redirect
        http.sessionManagement(smc -> smc.invalidSessionUrl("/invalidSession")
        // Concurrent session & Maximum session exceeds then force to ReLogin
             .maximumSessions(1).maxSessionsPreventsLogin(true))
             .requiresChannel(rcm -> rcm.anyRequest().requiresSecure()) // Allows Only HTTPs.
             .csrf(csrfConfig -> csrfConfig.disable())
             .authorizeHttpRequests((requests) -> requests
             .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards").authenticated()
             .requestMatchers("/notices", "/contact", "/error", "/register").permitAll());
        http.formLogin(withDefaults());
        http.httpBasic(htc -> htc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
        // For MVC App
        // http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()).accessDeniedPage("/denied"));
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * From Spring Security 6.3 version
     * @return
     */
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

}