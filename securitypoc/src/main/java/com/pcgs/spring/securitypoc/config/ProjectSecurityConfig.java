package com.pcgs.spring.securitypoc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {

        // httpSecurity.authorizeHttpRequests((requests) -> requests.anyRequest().permitAll());
        // httpSecurity.authorizeHttpRequests((requests) -> requests.anyRequest().denyAll());
        // httpSecurity.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());

        httpSecurity.csrf(csrfConfig -> csrfConfig.disable());

        httpSecurity.authorizeHttpRequests((requests) -> requests
                .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards").authenticated()
                .requestMatchers("/notices", "/contact", "/error","/register").permitAll());
//        httpSecurity.formLogin( httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer.disable());
//        httpSecurity.httpBasic(httpSecurityHttpBasicConfigurer -> httpSecurityHttpBasicConfigurer.disable());

        httpSecurity.formLogin(Customizer.withDefaults());
        httpSecurity.httpBasic(Customizer.withDefaults());
        return  httpSecurity.build();
    }

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
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
}
