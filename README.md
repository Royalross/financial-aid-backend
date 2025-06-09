# Financial Aid Backend

This project is a small Spring Boot 3 application that exposes authentication APIs backed by PostgreSQL.
It demonstrates user registration and JWT based login.

## Features

- Registration and login endpoints
- BCrypt password hashing
- JWT token generation using a configurable secret
- Global exception handling for validation errors

## Requirements

- Java 21
- Maven 3.9+
- PostgreSQL database

## Running the application

1. Adjust the database settings in `src/main/resources/application.properties` or provide them via environment variables.
2. Build and start the service:

```bash
./mvnw spring-boot:run
```

The API will be available at `http://localhost:8080`.

### Available endpoints

- `POST /auth/register` – create a new user
- `POST /auth/login` – authenticate and receive a JWT

## Running tests

Execute all unit tests with:

```bash
./mvnw test
```

## Configuration

JWT settings such as issuer, expiration time and secret are also defined in
`application.properties`. Be sure to change the secret for production deployments.
