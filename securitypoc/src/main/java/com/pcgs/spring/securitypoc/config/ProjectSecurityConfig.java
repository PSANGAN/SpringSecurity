package com.pcgs.spring.securitypoc.config;

import com.pcgs.spring.securitypoc.exceptionhandling.CustomAccessDeniedHandler;
import com.pcgs.spring.securitypoc.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import com.pcgs.spring.securitypoc.filter.CsrfCookieFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {

//    @Bean
//    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
//
//        // httpSecurity.authorizeHttpRequests((requests) -> requests.anyRequest().permitAll());
//        // httpSecurity.authorizeHttpRequests((requests) -> requests.anyRequest().denyAll());
//        // httpSecurity.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
//
//        httpSecurity.csrf(csrfConfig -> csrfConfig.disable());
//
//        httpSecurity.sessionManagement(smc -> smc.invalidSessionUrl("/invalidSession")
//                        .maximumSessions(3).maxSessionsPreventsLogin(true))
//                .requiresChannel(rcc -> rcc.anyRequest().requiresInsecure()); // Only HTTP
//
//        httpSecurity.authorizeHttpRequests((requests) -> requests
//                .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards").authenticated()
//                .requestMatchers("/notices", "/contact", "/error","/register","/invalidSession").permitAll());
//
////        httpSecurity.formLogin( httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer.disable());
////        httpSecurity.httpBasic(httpSecurityHttpBasicConfigurer -> httpSecurityHttpBasicConfigurer.disable());
//
//        httpSecurity.formLogin(Customizer.withDefaults());
//        //Only Works for HTTP
//        httpSecurity.httpBasic(htc -> htc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
//
//        // Global Level Authentication Exception
//        // httpSecurity.exceptionHandling(htc -> htc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
//
//        httpSecurity.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
//
//
//        return  httpSecurity.build();
//    }

    // Usage - InMemory Users Detail Services...
   /* @Bean
    public UserDetailsService userDetailsService() {
//        UserDetails readUser = User.withUsername("user").password("{noop}12345").authorities("read").build();
//        UserDetails adminUser = User.withUsername("admin").password("{noop}54321").authorities("admin").build();

        UserDetails readUser = User.withUsername("user").password("{noop}EazyBytes@12345").authorities("read").build();
        UserDetails adminUser = User.withUsername("admin")
                .password("{bcrypt}$2y$12$94uoojJAk6TRw9oyc1r.E.S38YsA8OYJ20xDCsM7hZdD/CFp4db/.")
                 .authorities("admin").build();

        return new InMemoryUserDetailsManager(adminUser,readUser);
    }
   */

    // Usage - JDBC Users Detail Services...
    /*
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }
    */

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        http.securityContext(contextConfig -> contextConfig.requireExplicitSave(false))
                .sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .cors(corsConfig -> corsConfig.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setMaxAge(3600L);
                        return config;
                    }
                }))
                .csrf(csrfConfig -> csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                        .ignoringRequestMatchers( "/contact","/register")
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .requiresChannel(rcc -> rcc.anyRequest().requiresInsecure()) // Only HTTP
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards", "/user").authenticated()
                        .requestMatchers("/notices", "/contact", "/error", "/register", "/invalidSession").permitAll());
        http.formLogin(withDefaults());
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
        return http.build();
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
}
