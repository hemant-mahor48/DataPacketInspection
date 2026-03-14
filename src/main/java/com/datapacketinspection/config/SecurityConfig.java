package com.datapacketinspection.config;

import com.datapacketinspection.security.AgentTokenFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(
            PasswordEncoder passwordEncoder,
            @Value("${app.security.admin-username}") String adminUsername,
            @Value("${app.security.admin-password}") String adminPassword,
            @Value("${app.security.analyst-username}") String analystUsername,
            @Value("${app.security.analyst-password}") String analystPassword) {
        return new InMemoryUserDetailsManager(
                User.withUsername(adminUsername)
                        .password(passwordEncoder.encode(adminPassword))
                        .roles("ADMIN", "ANALYST")
                        .build(),
                User.withUsername(analystUsername)
                        .password(passwordEncoder.encode(analystPassword))
                        .roles("ANALYST")
                        .build()
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AgentTokenFilter agentTokenFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/css/**", "/js/**", "/login", "/h2-console/**").permitAll()
                        .requestMatchers("/api/browser-agent/**").permitAll()
                        .requestMatchers("/api/history/firewall/**").hasRole("ADMIN")
                        .requestMatchers("/api/history/**").hasRole("ANALYST")
                        .requestMatchers("/api/**", "/").hasRole("ANALYST")
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))
                .addFilterBefore(agentTokenFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
