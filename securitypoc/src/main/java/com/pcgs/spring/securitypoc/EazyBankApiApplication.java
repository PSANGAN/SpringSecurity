package com.pcgs.spring.securitypoc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
//@EnableWebSecurity(debug = true)
/*@EnableJpaRepositories("com.pcgs.spring.securitypoc.repository")
@EntityScan("com.pcgs.spring.securitypoc.model")*/
public class EazyBankApiApplication {
	public static void main(String[] args) {
		SpringApplication.run(EazyBankApiApplication.class, args);
	}
}
