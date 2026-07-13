package com.lokesh.auth_server.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class DemoController {

    @GetMapping("/public")
    public Map<String, String> publicEndpoint() {
        return Map.of("message", "Anyone can see this — no token needed.");
    }

    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        // any authenticated user
        return Map.of(
                "subject", jwt.getSubject(),
                "username", jwt.getClaimAsString("preferred_username"),
                "email", jwt.getClaimAsString("email")
        );
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public Map<String, String> userArea() {
        return Map.of("message", "You have the USER role.");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> adminArea() {
        return Map.of("message", "You have the ADMIN role — privileged data.");
    }
}
