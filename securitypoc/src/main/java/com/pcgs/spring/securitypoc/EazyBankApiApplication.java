package com.pcgs.spring.securitypoc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication

/*@EnableJpaRepositories("com.pcgs.spring.securitypoc.repository")
@EntityScan("com.pcgs.spring.securitypoc.model")*/

public class EazyBankApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(EazyBankApiApplication.class, args);
	}

}
