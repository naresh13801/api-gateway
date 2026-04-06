# API Gateway Service

## Overview

This project is an API Gateway built with Spring Cloud Gateway. It routes incoming HTTP requests to downstream microservices and enforces JWT-based authentication and role-based access control.

The gateway exposes public auth endpoints and secures all other routes by validating the JWT token in the `Authorization: Bearer <token>` header. Valid tokens are parsed to extract the username and role, and the gateway forwards that information to downstream services using `X-Auth-User` and `X-Auth-Role` headers.

## Purpose

- Centralize routing for microservices under a single entry point.
- Proxy requests to the appropriate backend service based on URL path.
- Protect APIs with JWT authentication.
- Enforce role restrictions for admin and user-specific routes.
- Allow unauthenticated access only to auth-related endpoints.

## Configured Routes / Endpoints

The gateway routes requests to these downstream services:

- `/auth/**`
  - Forwarded to `http://localhost:8081`
  - Public endpoints used for authentication and registration.
  - No JWT token required.

- `/user/**`
  - Forwarded to `http://localhost:8082`
  - User-related APIs.
  - Requires a valid JWT token.
  - Accessible to users with role `USER` or `ADMIN`.

- `/services/**`
  - Forwarded to `http://localhost:8083`
  - Catalog or service-related APIs.
  - Requires a valid JWT token.

- `/booking/**`
  - Forwarded to `http://localhost:8084`
  - Booking-related APIs.
  - Requires a valid JWT token.

## Security Behavior

- Public routes:
  - `/auth/login`
  - `/auth/register`

- All other requests require:
  - `Authorization: Bearer <token>` header
  - Valid JWT token signed with the configured secret

- Role-based restrictions:
  - Paths starting with `/admin` are restricted to `ADMIN` role.
  - Paths starting with `/user` require `USER` or `ADMIN` role.

## JWT Configuration

The gateway uses the following JWT settings in `application.properties`:

- `jwt.secret`: shared secret for token signing
- `jwt.expiration`: token expiration time in milliseconds

## Running the Gateway

Start the gateway application using Maven or your IDE. The gateway listens on port `8080` by default.

Ensure downstream services are available on:

- `http://localhost:8081` for auth
- `http://localhost:8082` for user APIs
- `http://localhost:8083` for service/catalog APIs
- `http://localhost:8084` for booking APIs
