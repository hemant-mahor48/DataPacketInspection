package com.datapacketinspection.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class AgentTokenFilter extends OncePerRequestFilter {

    @Value("${app.agent.token}")
    private String expectedToken;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/browser-agent");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = request.getHeader("X-Agent-Token");
        if (token == null || !token.equals(expectedToken)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing or invalid agent token.");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
