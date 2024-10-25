package tn.isims.springSecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class SpringSecurityApplication {


	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}
}
