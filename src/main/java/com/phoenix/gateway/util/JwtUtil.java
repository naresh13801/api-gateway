package com.phoenix.gateway.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

import jakarta.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * Utility class for JWT token validation and claim extraction.
 * Provides secure token parsing and user information extraction for API Gateway validation.
 */
@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${jwt.secret}")
    private String SECRET;

    private Key key;

    @PostConstruct
    public void init() {
        key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }
    /**
     * Extracts all claims from a JWT token.
     * Uses modern JJWT 0.12.5+ API with proper key generation.
     *
     * @param token the JWT token
     * @return Claims object containing token data
     * @throws ExpiredJwtException if token has expired
     * @throws UnsupportedJwtException if token format is unsupported
     * @throws MalformedJwtException if token is malformed
     * @throws SignatureException if token signature is invalid
     * @throws IllegalArgumentException if token is null or empty
     */
    @SuppressWarnings("deprecation")
    public Claims getClaims(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("JWT token cannot be null or empty");
        }

        try {
            return Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        } catch (ExpiredJwtException e) {
            logger.warn("JWT token has expired: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token format is unsupported: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
            throw e;
        } catch (SignatureException e) {
            logger.error("JWT token signature validation failed: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            logger.error("JWT token parsing failed: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Validates if a JWT token is valid and not expired.
     * Returns boolean instead of throwing exceptions for better control flow.
     *
     * @param token the JWT token
     * @return true if token is valid and not expired, false otherwise
     */
    public boolean isTokenValid(String token) {
        try {
            getClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            logger.debug("Token validation failed - expired");
            return false;
        } catch (Exception e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Validates a JWT token and throws exception if invalid.
     * Kept for backward compatibility with gateway filter chains.
     *
     * @param token the JWT token
     * @throws ExpiredJwtException if token has expired
     * @throws MalformedJwtException if token is malformed
     * @throws SignatureException if signature is invalid
     * @throws IllegalArgumentException if token is null or invalid
     */
    public void validateToken(String token) {
        getClaims(token);
    }

    /**
     * Extracts the username (subject) from a JWT token.
     *
     * @param token the JWT token
     * @return the username from token subject
     * @throws ExpiredJwtException if token has expired
     * @throws Exception if token is invalid
     */
    public String extractUsername(String token) {
        String username = getClaims(token).getSubject();
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username claim is missing in token");
        }
        return username;
    }

    /**
     * Extracts the user role from a JWT token.
     *
     * @param token the JWT token
     * @return the user role from token claims
     * @throws ExpiredJwtException if token has expired
     * @throws Exception if token is invalid
     */
    public String extractRole(String token) {
        Object roleClaim = getClaims(token).get("role");
        if (roleClaim == null) {
            throw new IllegalArgumentException("Role claim is missing in token");
        }
        return roleClaim.toString();
    }
}