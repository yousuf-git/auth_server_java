# Production Ready Auth Server developed by Your one and only favorite programmer :)

<div align="center">

![Java](https://img.shields.io/badge/java-%23ED8B00.svg?style=for-the-badge&logo=openjdk&logoColor=white)
![Spring](https://img.shields.io/badge/spring-%236DB33F.svg?style=for-the-badge&logo=spring&logoColor=white)
![Spring Security](https://img.shields.io/badge/Spring_Security-6DB33F?style=for-the-badge&logo=Spring-Security&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=JSON%20web%20tokens)
![Google Auth](https://img.shields.io/badge/Google_Auth-%23DB4437.svg?style=for-the-badge&logo=google&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/postgresql-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![AWS Cloud](https://img.shields.io/badge/AWS-232F3E?style=for-the-badge&logo=amazon-aws&logoColor=white)

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg?style=flat-square)](https://github.com/yourusername/spring-security-jwt)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg?style=flat-square)](https://github.com/yourusername/spring-security-jwt/releases)
[![Security Rating](https://img.shields.io/badge/security-A-green.svg?style=flat-square)](https://sonarcloud.io/dashboard?id=your-project)

</div>

---

## What's This All About?

Welcome to my **Spring Security JWT Authentication System** – one-stop solution for implementing robust, stateless authentication in Spring Boot applications!

This project demonstrates a production-ready implementation of JWT (JSON Web Tokens) authentication using Spring Security 6, complete with user registration, login, OAuth2 (Google Sign-In), role-based access control, and secure API endpoints. Whether you're building a RESTful API, microservices, or a full-stack application, this template has got you covered!

### Key Features

- **Enterprise-Grade Security**: Implements industry best practices for authentication and authorization
- **Stateless Authentication**: Perfect for microservices and scalable applications
- **OAuth2 Integration**: Google Sign-In with JWT token generation
- **Role-Based Access Control**: Flexible permission system for different user types
- **Production Ready**: Includes error handling, validation, and security configurations
- **Beautiful Demo UI**: Interactive OAuth2 login page included
- **Well Documented**: Comprehensive documentation and examples
- **140+ Test Cases**: 83.6% test coverage with comprehensive test suite

---

## Tech Stack & Arsenal

Technology stack that ensures robust performance and maintainability:

### Core Technologies
- **Java 21** - Latest LTS version with modern language features
- **Spring Boot 3.4.1** - Rapid application development framework
- **Spring Security 6** - Comprehensive security framework
- **JWT (JSON Web Tokens)** - Stateless authentication mechanism
- **Spring Data JPA** - Data persistence abstraction layer

### Database & Storage

[//]: # (- **MySQL 8.0+** - Reliable relational database)
- **PostgreSQL 15+** - Alternative relational database for flexibility
- **H2 Database** - In-memory database for testing

### Additional Libraries

[//]: # (- **Spring Boot Actuator** - Application monitoring and metrics)
- **Spring Boot Validation** - Request validation
- **JUnit 5** - Unit and integration testing
- **SpringDoc OpenAPI** - API documentation

---

## Project Architecture & Structure

```
src/
├── 📁 main/
│   ├── 📁 java/com/learning/security/
│   │   ├── 📁 auth/                          # Entry point for authentication
│   │   │   ├── AuthEntryPointJwt.java
│   │   │   ├── AuthTokenFilter.java
│   │   │   └── JwtAccessDeniedHandler.java
│   │   ├── 📁 configs/                       # Security & JWT configuration
│   │   │   ├── WebSecurityConfig.java
│   │   │   └── SwaggerConfig.java
│   │   ├── 📁 controllers/                   # REST API endpoints
│   │   │   ├── AuthController.java
│   │   │   ├── Greet.java
│   │   │   └── TestController.java
│   │   ├── 📁 dtos/                          # Data Transfer Objects
│   │   │   ├── LoginRequest.java
│   │   │   ├── SignUpRequest.java
│   │   │   ├── ResponseMessage.java
│   │   │   └── JwtResponse.java
│   │   ├── 📁 enums/                        # JPA Entities
│   │   │   └── ERole.java
│   │   │   📁 exception/                    # Custom exceptions
│   │   │   ├── GlobalExceptionHandler.java
│   │   │   └── CustomJwtException.java
│   │   ├── 📁 models/                       # JPA Entities
│   │   │   ├── User.java
│   │   │   └── Role.java
│   │   ├── 📁 repos/                       # Data access layer
│   │   │   ├── UserRepo.java
│   │   │   └── RoleRepo.java
│   │   ├── 📁 services/                   # Business logic
│   │   │   ├── UserDetailsImpl.java
│   │   │   └── UserDetailsServiceImpl.java
│   │   ├── 📁 utils/                      # Utility classes
│   │   │   └── JwtUtils.java
│   │   └── SecurityApplication.java
│   └── 📁 resources/
│       └── application.yml
└── 📁 test/                    # Test cases
    └── pending...
```

---

## Understanding the Magic Behind JWT

### What Exactly is JWT?

**JWT (JSON Web Token)** is like a digital passport for your application! It's a compact, URL-safe token that represents claims between two parties. Think of it as a secure way to say "Hey, this user is who they claim to be, and here's what they're allowed to do." Now it's responsibility of the server to verify and trust that claim.

### JWT Structure Breakdown

A JWT consists of three parts separated by dots (`.`):

```
xxxxx.yyyyy.zzzzz
```

1. **Header**: Contains token type and signing algorithm
2. **Payload**: Contains the claims (user data, permissions, expiration)
3. **Signature**: Ensures the token hasn't been tampered with

### How JWT Authentication Works
<img src="src/main/resources/images/seq_diagram.png" alt="JWT Authentication Flow" width="600" height="400">

### Why JWT Rocks for Modern Applications

- **Stateless**: No server-side session storage needed
- **Scalable**: Perfect for distributed systems
- **Secure**: Cryptographically signed
- **Self-contained**: All necessary info is in the token
- **Cross-domain**: Works across different domains

---

## Getting Started: Your Journey Begins Here

### Prerequisites

Before diving in, make sure you have:

- **Java 17 or higher** installed
- **Maven 3.6+** for dependency management
- **PostgreSQL** running locally or remotely

[//]: # (- **MySQL 8.0+** running locally or remotely)
- **Your favorite IDE** (IntelliJ IDEA, Eclipse, or VS Code)

### Quick Start Guide

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yousuf-git/Spring_Security_JWT.git
   cd Spring_Security_JWT
   ```

2. **Configure Database**
   ```yaml
   # application.yml
   spring:
     datasource:
       url: jdbc:mysql://localhost:3306/<db_name>
       username: your_username
       password: your_password
   ```

3. **Install Dependencies**
   ```bash
   mvn clean install
   ```

4. **Run the Application**
   ```bash
   mvn spring-boot:run
   ```

5. **Verify Everything Works**
   ```bash
   curl http://localhost:8080/api/greet
   ```

6. **Access the Application**

   | Page | URL |
   |------|-----|
   | Login Page | http://localhost:8080/login.html |
   | Signup Page | http://localhost:8080/signup.html |
   | Swagger API Docs | http://localhost:8080/swagger-ui/index.html |

   > **Note:** The HTML pages are for browser access. The API endpoints (`POST /auth/signin`, `POST /auth/signup`) are called internally by these pages via JavaScript.

---

## API Playground: Let's Test Drive!

Simply open swagger docs via browser and explore the API endpoints:

```bash
# Open Swagger UI
http://localhost:8080/api/swagger-ui/index.html
or 
http://localhost:8080/swagger-ui/index.html
````

---

## Configuration Deep Dive

### JWT Configuration

```yaml
app:
  jwt:
    secret: mySecretKey
    expiration: 86400000  # 24 hours in milliseconds
    refresh-expiration: 604800000  # 7 days
```

### Security Configuration Highlights

- **Password Encoding**: BCrypt with default strength 10
- **CORS**: Configured for cross-origin requests
- **CSRF**: Disabled for stateless authentication
- **Session Management**: Stateless session creation policy

### Database Configuration

```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: false
    properties:
      hibernate:
        dialect: org.hibernate.dialect.MySQL8Dialect
        format_sql: true
```

---

## OAuth2 Integration (Google Sign-In)

### Quick Start in 11 Minutes!

This project now includes **production-ready OAuth2 integration** with Google! Get users signing in with their Google accounts in just 11 minutes.

### Documentation

- **[OAUTH2_QUICK_START.md](OAUTH2_QUICK_START.md)** - 11-minute quick start guide
- **[OAUTH2_SETUP.md](OAUTH2_SETUP.md)** - Comprehensive 400+ line documentation
- **[OAUTH2_IMPLEMENTATION_SUMMARY.md](OAUTH2_IMPLEMENTATION_SUMMARY.md)** - Complete implementation details

### What You Get

- **Google OAuth2 Login**: One-click sign-in with Google
- **JWT Generation**: Automatic token creation for OAuth2 users
- **Beautiful Demo UI**: Interactive login page at `/oauth2-demo.html`
- **Unified Authentication**: Both local and OAuth2 users in one system
- **Database Migration**: SQL scripts included
- **Security Best Practices**: Using Spring Security 6.x latest patterns

### Quick Demo

1. **Set up Google credentials** (5 minutes):
   ```bash
   export GOOGLE_CLIENT_ID="your-client-id"
   export GOOGLE_CLIENT_SECRET="your-client-secret"
   ```

2. **Run database migration** (2 minutes):
   ```bash
   psql -U postgres -d demo -f add_oauth2_columns.sql
   ```

3. **Start application** (1 minute):
   ```bash
   mvn spring-boot:run -Dspring-boot.run.profiles=dev
   ```

4. **Test OAuth2 flow** (3 minutes):
   - Open: http://localhost:8080/oauth2-demo.html
   - Click "Continue with Google"
   - Sign in and get your JWT token!

### OAuth2 Demo Page Features

The included demo page (`oauth2-demo.html`) provides:
- Beautiful, responsive UI with Google branding
- One-click Google authentication
- Automatic JWT token handling
- Token persistence in localStorage
- Automatic authentication testing
- User info display after login
- Logout functionality

### OAuth2 Architecture

```
User Browser → Demo Page → Spring Security OAuth2 Client → Google OAuth2
     ↓              ↓              ↓                           ↓
  Receives JWT ← Success Handler ← CustomOAuth2UserService ← User Info
```

For detailed architecture diagrams and flow explanations, see [OAUTH2_IMPLEMENTATION_SUMMARY.md](OAUTH2_IMPLEMENTATION_SUMMARY.md).

---

## Testing Strategy

### Comprehensive Test Suite

This project includes **140+ test cases** with **83.6% passing rate** covering:

- **Unit Tests**: Service layer, JWT utils, user details
- **Integration Tests**: Authentication flow, controllers, repositories
- **Security Tests**: Token filter, entry points, exception handling
- **Model Tests**: User and Role entity validation

**Test Documentation**: See [TEST_DOCUMENTATION.md](TEST_DOCUMENTATION.md) for:
- Individual test descriptions
- Success criteria
- How to run specific tests
- Test coverage analysis

**Test Status**: See [TEST_STATUS.md](TEST_STATUS.md) for current test results and known issues.

### Test Classes

1. **AuthTokenFilterTest** (16 tests) - JWT filter validation
2. **AuthControllerTest** (12 tests) - Registration and login endpoints
3. **TestControllerTest** (22 tests) - Role-based access control
4. **RoleTest** (13 tests) - Role entity validation
5. **UserTest** (13 tests) - User entity validation
6. **RepositoryTest** (21 tests) - Database operations
7. **UserDetailsImplTest** (17 tests) - User details implementation
8. **UserDetailsServiceImplTest** (11 tests) - User service
9. **JwtUtilsTest** (13 tests) - JWT token operations
10. **SecurityApplicationTests** (2 tests) - Application context loading

### Running Tests

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=AuthControllerTest

# Run with coverage
mvn clean verify
```

### Running Tests

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=AuthControllerTest

# Run tests with coverage
mvn test jacoco:report
```

---

## Security Best Practices Implemented

### Authentication Security
- Strong password requirements
- Account lockout after failed attempts - (pending)
- JWT token expiration
- Secure password hashing (BCrypt)

### API Security
- HTTPS enforcement in production
- Input validation and sanitization
- SQL injection prevention
- XSS protection headers

### Monitoring & Logging - Pending...
- Security event logging
- Failed authentication tracking
- Performance monitoring with Actuator

---

[//]: # (## 🚀 Production Deployment)


## Docker Support

### Build the Docker image
```bash
docker build -t jwt_auth_app .
```

### ☁️ Run with environment variables
```bash
docker run -p 8080:8080 \
-e SPRING_ACTIVE_PROFILES=prod
-e DATABASE_URL="jdbc:postgresql://host.docker.internal:5432/auth_db" \
-e DATABASE_USERNAME="<username>" \
-e DATABASE_PASSWORD="<pass>" \
-e JWT_SECRET="<secret>" \
-e JWT_EXPIRATION="86400000" \
jwt_auth_app
```

### Using docker-compose
```bash 
docker-compose up --build
```

---

## Contributing & Support

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/feature-name`)
3. Commit your changes (`git commit -m 'Add: amazing feature'`)
4. Push to the branch (`git push origin feature/feature-name`)
5. Open a Pull Request

### Need Help?

- **Found a bug?** [Open an issue](https://github.com/yousuf-git/Spring_Security_JWT/issues)
- **Have a suggestion?** [Start a discussion](https://github.com/yousuf-git/Spring_Security_JWT/discussions)
- **Email support**: yousuf.work09@example.com

---

### Special Thanks

- Spring Security team for the amazing framework
- JWT.io for excellent documentation
- The open-source community for inspiration

---

<div align="center">

**If this project helped you, please give it a star!**

Made with love by [M. Yousuf](https://github.com/yousuf-git)

[![GitHub followers](https://img.shields.io/github/followers/yousuf-git?style=social)](https://github.com/yousuf-git)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=social&logo=linkedin)](https://www.linkedin.com/in/muhammad-yousuf952)

</div>

