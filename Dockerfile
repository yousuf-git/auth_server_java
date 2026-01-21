# Multi-stage build for better image size optimization
FROM maven:3.9.9-eclipse-temurin-21 AS build

WORKDIR /app

# Copy pom.xml first for better layer caching
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:21-jre-alpine

# Create non-root user for security
RUN addgroup -g 1001 appgroup && adduser -u 1001 -G appgroup -s /bin/sh -D appuser

WORKDIR /app

# Copy the built JAR from build stage
COPY --from=build /app/target/*.war app.war

# Change ownership to non-root user
RUN chown -R appuser:appgroup /app
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/actuator/health || exit 1

# Set default environment variables
#ENV SPRING_PROFILES_ACTIVE=dev
ENV PORT=8080
#ENV JWT_EXPIRATION=86400000

# Run the application
ENTRYPOINT ["java", "-jar", "/app/app.war"]