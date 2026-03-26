package com.phoenix.gateway.filter;

import com.phoenix.gateway.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.*;
import org.springframework.core.Ordered;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    @Autowired
    private JwtUtil jwtUtil;

    // For below APIs no token required
    private static final List<String> PUBLIC_ROUTES = List.of(
            "/auth/login",
            "/auth/register");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();

        // Skip public routes
        if (PUBLIC_ROUTES.stream().anyMatch(path::equals)) {
            return chain.filter(exchange);
        }

        // Get Authorization header
        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return unauthorized(exchange);
        }

        String token = authHeader.substring(7);

        try {
            // Validate token
            jwtUtil.validateToken(token);

            // Extract data
            String username = jwtUtil.extractUsername(token);
            String role = jwtUtil.extractRole(token);

            // ROLE-BASED ACCESS CONTROL

            // ADMIN only endpoints
            if (path.startsWith("/admin") && !"ADMIN".equals(role)) {
                return forbidden(exchange);
            }

            // USER endpoints (optional restriction)
            if (path.startsWith("/user") && !(role.equals("USER") || role.equals("ADMIN"))) {
                return forbidden(exchange);
            }
            // Forward user info to services
            var mutatedRequest = exchange.getRequest().mutate()
                    .header("X-Auth-User", username)
                    .header("X-Auth-Role", role)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (Exception e) {
            return unauthorized(exchange);
        }
    }

    private Mono<Void> forbidden(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
