package com.learning.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test to verify Spring Boot application context loads correctly
 * Tests that all beans are properly configured and the application can start
 */
@SpringBootTest
class SecurityApplicationTests {

	@Autowired
	private ApplicationContext applicationContext;

	@Test
	void contextLoads() {
		// Verify that the application context loaded successfully
		assertNotNull(applicationContext, "Application context should not be null");
	}

	@Test
	void verifyMainBeansExist() {
		// Verify critical beans are present in the context
		assertNotNull(applicationContext.getBean("userRepo"), "UserRepo bean should exist");
		assertNotNull(applicationContext.getBean("roleRepo"), "RoleRepo bean should exist");
		assertNotNull(applicationContext.getBean("jwtUtils"), "JwtUtils bean should exist");
	}

}
