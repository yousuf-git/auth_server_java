# Spring Security JWT - Test Suite

This document provides comprehensive information about the test suite for the Spring Security JWT Authentication & Authorization Server.

## 📋 Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Test Coverage](#test-coverage)
- [Running Tests](#running-tests)
- [Test Categories](#test-categories)
- [Technologies Used](#technologies-used)
- [Test Configuration](#test-configuration)

## 🎯 Overview

The test suite provides comprehensive coverage for the Spring Security JWT application, including:
- **Unit Tests**: Testing individual components in isolation
- **Integration Tests**: Testing component interactions and API endpoints
- **Repository Tests**: Testing database operations with H2 in-memory database

## 📁 Test Structure

```
src/test/java/com/learning/security/
├── models/
│   ├── UserTest.java              # User entity validation tests
│   └── RoleTest.java              # Role entity and enum tests
├── services/
│   ├── UserDetailsImplTest.java          # UserDetailsImpl tests
│   └── UserDetailsServiceImplTest.java   # User loading service tests
├── utils/
│   └── JwtUtilsTest.java          # JWT generation and validation tests
├── controllers/
│   ├── AuthControllerTest.java    # Signup and signin endpoint tests
│   └── TestControllerTest.java    # Role-based access control tests
├── auth/
│   └── AuthTokenFilterTest.java   # JWT filter tests
└── repos/
    └── RepositoryTest.java        # Database operation tests
```

## ✅ Test Coverage

### 1. Model Tests (UserTest.java, RoleTest.java)
- ✓ Entity validation (@NotBlank, @NotNull)
- ✓ Unique constraints (username, email)
- ✓ Role enum validation
- ✓ Entity relationships (User-Role many-to-many)
- ✓ Lombok annotations (constructors, getters, setters)
- ✓ Equals and hashCode methods

### 2. Service Tests

#### UserDetailsImplTest.java
- ✓ Building UserDetails from User entity
- ✓ Single and multiple role handling
- ✓ Spring Security interface methods (isEnabled, isAccountNonExpired, etc.)
- ✓ Role conversion to GrantedAuthority
- ✓ All constructors and data access methods

#### UserDetailsServiceImplTest.java
- ✓ Loading user by username (success and failure)
- ✓ UsernameNotFoundException handling
- ✓ Multiple roles support
- ✓ User details preservation (email, authorities)
- ✓ Repository interaction verification

### 3. Utility Tests (JwtUtilsTest.java)
- ✓ JWT token generation
- ✓ Token validation (valid, expired, malformed, invalid signature)
- ✓ Username extraction from token
- ✓ Token expiration time verification
- ✓ Issuer and type validation
- ✓ Error handling (null, empty, whitespace tokens)

### 4. Controller Tests

#### AuthControllerTest.java
- ✓ User signup (success and validation)
- ✓ Username/email uniqueness checks
- ✓ Default and custom role assignment
- ✓ Multiple roles handling
- ✓ Invalid role rejection
- ✓ User signin with JWT generation
- ✓ Field validation (@Valid annotations)

#### TestControllerTest.java
- ✓ Public endpoint access (without authentication)
- ✓ User role access control
- ✓ Moderator role access control
- ✓ Admin role access control
- ✓ Role hierarchy enforcement
- ✓ Combined roles access
- ✓ CORS headers verification

### 5. Filter Tests (AuthTokenFilterTest.java)
- ✓ JWT token extraction from Authorization header
- ✓ Valid token authentication setup
- ✓ Invalid token handling
- ✓ Expired token handling
- ✓ Public endpoint bypass
- ✓ Security context population
- ✓ User authorities preservation
- ✓ Exception handling

### 6. Repository Tests (RepositoryTest.java)
- ✓ User CRUD operations
- ✓ Username lookup
- ✓ Email existence checks
- ✓ Multiple roles persistence
- ✓ Unique constraint validation
- ✓ Role CRUD operations
- ✓ Role lookup by enum
- ✓ User-Role cascade behavior
- ✓ Timestamp auto-generation

## 🚀 Running Tests

### Run All Tests
```bash
mvn test
```

### Run Specific Test Class
```bash
mvn test -Dtest=UserTest
mvn test -Dtest=AuthControllerTest
```

### Run Tests with Coverage
```bash
mvn test jacoco:report
```

### Run Tests in IDE
- **IntelliJ IDEA**: Right-click on test class/method → Run
- **Eclipse**: Right-click on test class/method → Run As → JUnit Test
- **VS Code**: Click "Run Test" or "Debug Test" above test methods

## 📚 Test Categories

### Unit Tests
- **Purpose**: Test individual components in isolation
- **Examples**: UserTest, RoleTest, JwtUtilsTest, UserDetailsImplTest
- **Characteristics**: Fast, no external dependencies, mock collaborators

### Integration Tests
- **Purpose**: Test component interactions and API endpoints
- **Examples**: AuthControllerTest, TestControllerTest
- **Characteristics**: Test with Spring context, mock some beans

### Repository Tests
- **Purpose**: Test database operations
- **Examples**: RepositoryTest
- **Characteristics**: Use H2 in-memory database, test data persistence

## 🛠 Technologies Used

- **JUnit 5**: Test framework
- **Mockito**: Mocking framework for unit tests
- **Spring Boot Test**: Testing support for Spring applications
- **Spring Security Test**: Security testing utilities (@WithMockUser)
- **MockMvc**: Testing Spring MVC controllers
- **H2 Database**: In-memory database for repository tests
- **TestEntityManager**: JPA testing utilities
- **AssertJ**: Fluent assertions (via Spring Boot Test)

## ⚙️ Test Configuration

### application-test.yml
Located at `src/test/resources/application-test.yml`, provides:
- H2 in-memory database configuration
- JPA settings for test environment
- JWT secret and expiration for testing
- Logging levels for test execution

### Key Settings:
```yaml
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
  jpa:
    hibernate:
      ddl-auto: create-drop
```

## 📊 Test Metrics

- **Total Test Classes**: 9
- **Total Test Methods**: 150+
- **Coverage Areas**:
  - Models & Entities: ✓
  - Services & Business Logic: ✓
  - Controllers & API Endpoints: ✓
  - Security & Authentication: ✓
  - Data Access & Repositories: ✓
  - Utilities & Helpers: ✓

## 🔍 Key Testing Patterns

### 1. AAA Pattern (Arrange-Act-Assert)
All tests follow this structure:
```java
@Test
void testMethod() {
    // Given (Arrange)
    // ... setup test data
    
    // When (Act)
    // ... execute the method under test
    
    // Then (Assert)
    // ... verify the results
}
```

### 2. Mocking External Dependencies
```java
@MockBean
private UserRepo userRepo;

when(userRepo.findByUsername("test")).thenReturn(Optional.of(user));
```

### 3. Security Testing
```java
@WithMockUser(username = "admin", roles = {"ADMIN"})
@Test
void testAdminEndpoint() {
    // Test with admin role
}
```

### 4. Exception Testing
```java
assertThrows(UsernameNotFoundException.class, 
    () -> service.loadUserByUsername("nonexistent")
);
```

## 📝 Best Practices Followed

1. ✓ **Clear Test Names**: Descriptive method names following `test_<method>_<scenario>` pattern
2. ✓ **One Assertion Per Test**: Each test verifies a specific behavior
3. ✓ **Test Independence**: Tests don't depend on execution order
4. ✓ **Comprehensive Coverage**: Happy paths, edge cases, and error scenarios
5. ✓ **Fast Execution**: Unit tests run in milliseconds
6. ✓ **Readable Tests**: Clear Given-When-Then structure
7. ✓ **Helper Methods**: Reusable test data creation methods
8. ✓ **Cleanup**: Proper setup and teardown (e.g., SecurityContextHolder.clearContext())

## 🐛 Debugging Tests

### Enable Debug Logging
Modify `application-test.yml`:
```yaml
logging:
  level:
    com.learning.security: DEBUG
    org.springframework.security: DEBUG
```

### Run Single Test in Debug Mode
```bash
mvn test -Dtest=TestClassName#testMethodName -X
```

## 🤝 Contributing

When adding new features:
1. Write tests first (TDD approach)
2. Ensure all existing tests pass
3. Maintain test coverage above 80%
4. Follow existing test patterns and naming conventions
5. Document complex test scenarios

## 📄 License

Same as the main project.

---

**Author**: M. Yousuf  
**Last Updated**: December 2025
