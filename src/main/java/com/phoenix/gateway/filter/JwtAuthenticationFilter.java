package com.phoenix.gateway.filter;

import com.phoenix.gateway.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.*;
import org.springframework.core.Ordered;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthenticationFilter implements GlobalFilter {

    private final JwtUtil jwtUtil;

    // APIs that don't require JWT
    private static final List<String> PUBLIC_ROUTES = List.of(
            "/auth/login",
            "/auth/register"
    );

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(
            ServerWebExchange exchange,
            GatewayFilterChain chain) {

        String path = exchange.getRequest()
                .getURI()
                .getPath();
        System.out.println("========== JWT FILTER ==========");
    System.out.println("Path: " + path);


        // ==========================================
        // 1. PUBLIC ROUTES
        // ==========================================

        if (PUBLIC_ROUTES.stream().anyMatch(path::equals)) {
            return chain.filter(exchange);
        }

        // ==========================================
        // 2. GET AUTHORIZATION HEADER
        // ==========================================

        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        // No Authorization header
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return unauthorized(exchange);
        }

        // ==========================================
        // 3. EXTRACT JWT
        // ==========================================

        String token = authHeader.substring(7);

        try {

            // ==========================================
            // 4. VALIDATE JWT
            // ==========================================

            if (!jwtUtil.isTokenValid(token)) {
                return unauthorized(exchange);
            }

            // ==========================================
            // 5. EXTRACT USER INFORMATION
            // ==========================================

            String username = jwtUtil.extractUsername(token);
            String role = jwtUtil.extractRole(token);

            // ==========================================
            // 6. ROLE-BASED AUTHORIZATION
            // ==========================================

            // ADMIN-only endpoints
            if (path.startsWith("/admin")
                    && !"ADMIN".equals(role)) {

                return forbidden(exchange);
            }

            // USER endpoints
            if (path.startsWith("/user")
                    && !("USER".equals(role)
                            || "ADMIN".equals(role))) {

                return forbidden(exchange);
            }

            // ==========================================
            // 7. FORWARD USER INFORMATION
            // ==========================================

            List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    authorities);

            ServerWebExchange mutatedExchange = exchange.mutate()
                    .request(request -> request
                            .headers(headers -> {
                                headers.remove("X-Auth-User");
                                headers.remove("X-Auth-Role");

                                headers.add("X-Auth-User", username);
                                headers.add("X-Auth-Role", role);
                            }))
                    .build();

            return chain.filter(mutatedExchange)
                    .contextWrite(
                            ReactiveSecurityContextHolder.withAuthentication(
                                    authentication));

        } catch (Exception e) {

            // Invalid / expired / malformed JWT
            return unauthorized(exchange);
        }
    }

    // ==========================================
    // 401 UNAUTHORIZED
    // ==========================================

    private Mono<Void> unauthorized(
            ServerWebExchange exchange) {

        exchange.getResponse()
                .setStatusCode(HttpStatus.UNAUTHORIZED);

        return exchange.getResponse()
                .setComplete();
    }

    // ==========================================
    // 403 FORBIDDEN
    // ==========================================

    private Mono<Void> forbidden(
            ServerWebExchange exchange) {

        exchange.getResponse()
                .setStatusCode(HttpStatus.FORBIDDEN);

        return exchange.getResponse()
                .setComplete();
    }
}
