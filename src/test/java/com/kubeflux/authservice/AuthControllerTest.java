package com.kubeflux.authservice;

import com.kubeflux.authservice.controller.AuthController;
import com.kubeflux.authservice.dto.AuthRequest;
import com.kubeflux.authservice.model.Role;
import com.kubeflux.authservice.model.User;
import com.kubeflux.authservice.repository.UserRepository;
import com.kubeflux.authservice.security.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthController authController;

    @Test
    void register_failsIfEmailAlreadyExists() {
        AuthRequest request = new AuthRequest();
        request.setEmail("existing@test.com");
        request.setPassword("pass123");

        when(userRepository.findByEmail("existing@test.com"))
                .thenReturn(Optional.of(new User()));

        ResponseEntity<?> response = authController.register(request);

        assertEquals(400, response.getStatusCode().value());
        verify(userRepository, never()).save(any());
    }

    @Test
    void login_returnsTokenForValidCredentials() {
        AuthRequest request = new AuthRequest();
        request.setEmail("test@test.com");
        request.setPassword("test123");

        User user = new User();
        user.setEmail("test@test.com");
        user.setPassword("hashedPassword");
        user.setRole(Role.USER);

        when(userRepository.findByEmail("test@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("test123", "hashedPassword")).thenReturn(true);
        when(jwtUtil.generateToken("test@test.com", "USER")).thenReturn("fake-jwt-token");

        ResponseEntity<?> response = authController.login(request);

        assertEquals(200, response.getStatusCode().value());
    }

    @Test
    void login_rejectsInvalidPassword() {
        AuthRequest request = new AuthRequest();
        request.setEmail("test@test.com");
        request.setPassword("wrongpass");

        User user = new User();
        user.setEmail("test@test.com");
        user.setPassword("hashedPassword");

        when(userRepository.findByEmail("test@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrongpass", "hashedPassword")).thenReturn(false);

        ResponseEntity<?> response = authController.login(request);

        assertEquals(401, response.getStatusCode().value());
    }
}