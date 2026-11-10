package com.example.identityservice.service;

import com.example.identityservice.dto.LoginRequest;
import com.example.identityservice.dto.LoginResponse;
import com.example.identityservice.dto.RegisterRequest;
import com.example.identityservice.dto.UserResponse;
import com.example.identityservice.entity.User;
import com.example.identityservice.exception.DuplicateResourceException;
import com.example.identityservice.exception.ResourceNotFoundException;
import com.example.identityservice.repository.UserRepository;
import com.example.identityservice.service.impl.UserServiceImpl;
import com.example.identityservice.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtUtil jwtUtil;

    @Spy
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private UserServiceImpl userService;

    private RegisterRequest registerRequest;

    @BeforeEach
    void setUp() {
        userService = new UserServiceImpl(userRepository, passwordEncoder, jwtUtil);
        registerRequest = new RegisterRequest("john_doe", "password123", "USER");
    }

    @Test
    @DisplayName("Should successfully register a new user with BCrypt hashed password")
    void register_Success() {
        when(userRepository.existsByUsername("john_doe")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User u = invocation.getArgument(0);
            u.setId("mock-uuid-1234");
            return u;
        });

        UserResponse response = userService.register(registerRequest);

        assertNotNull(response);
        assertEquals("mock-uuid-1234", response.getId());
        assertEquals("john_doe", response.getUsername());
        assertEquals("USER", response.getRole());

        // Verify password was hashed with BCrypt
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository, times(1)).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertNotEquals("password123", savedUser.getPassword());
        assertTrue(savedUser.getPassword().startsWith("$2a$") || savedUser.getPassword().startsWith("$2b$"));
        assertTrue(passwordEncoder.matches("password123", savedUser.getPassword()));
    }

    @Test
    @DisplayName("Should throw DuplicateResourceException when username already exists")
    void register_DuplicateUsername_ThrowsException() {
        when(userRepository.existsByUsername("john_doe")).thenReturn(true);

        assertThrows(DuplicateResourceException.class, () -> userService.register(registerRequest));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should successfully authenticate and return token when login credentials match")
    void login_Success() {
        String hashedPassword = passwordEncoder.encode("password123");
        User user = new User("u-1", "john_doe", hashedPassword, "USER");
        when(userRepository.findByUsername("john_doe")).thenReturn(Optional.of(user));
        when(jwtUtil.generateToken(user)).thenReturn("mock.login.jwt.token");

        LoginRequest loginRequest = new LoginRequest("john_doe", "password123");
        LoginResponse response = userService.login(loginRequest);

        assertNotNull(response);
        assertEquals("mock.login.jwt.token", response.getAccessToken());
        assertEquals("Bearer", response.getTokenType());
        verify(passwordEncoder, times(1)).matches("password123", hashedPassword);
    }

    @Test
    @DisplayName("Should throw BadCredentialsException when password does not match")
    void login_WrongPassword_ThrowsBadCredentials() {
        String hashedPassword = passwordEncoder.encode("password123");
        User user = new User("u-1", "john_doe", hashedPassword, "USER");
        when(userRepository.findByUsername("john_doe")).thenReturn(Optional.of(user));

        LoginRequest loginRequest = new LoginRequest("john_doe", "wrongPassword");

        BadCredentialsException exception = assertThrows(BadCredentialsException.class,
                () -> userService.login(loginRequest));
        assertEquals("Bad credentials", exception.getMessage());
        verify(jwtUtil, never()).generateToken(any());
    }

    @Test
    @DisplayName("Should throw BadCredentialsException when username is not found")
    void login_UserNotFound_ThrowsBadCredentials() {
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        LoginRequest loginRequest = new LoginRequest("nonexistent", "password123");

        BadCredentialsException exception = assertThrows(BadCredentialsException.class,
                () -> userService.login(loginRequest));
        assertEquals("Bad credentials", exception.getMessage());
        verify(jwtUtil, never()).generateToken(any());
    }

    @Test
    @DisplayName("Should generate token when user is found in database")
    void generateTestToken_Success() {
        User user = new User("u-1", "john_doe", "hashed_pwd", "USER");
        when(userRepository.findByUsername("john_doe")).thenReturn(Optional.of(user));
        when(jwtUtil.generateToken(user)).thenReturn("mock.jwt.token");

        String token = userService.generateTestToken("john_doe");

        assertEquals("mock.jwt.token", token);
        verify(userRepository, times(1)).findByUsername("john_doe");
        verify(jwtUtil, times(1)).generateToken(user);
    }

    @Test
    @DisplayName("Should throw ResourceNotFoundException when user is not found")
    void generateTestToken_UserNotFound_ThrowsException() {
        when(userRepository.findByUsername("unknown_user")).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> userService.generateTestToken("unknown_user"));
        verify(jwtUtil, never()).generateToken(any());
    }
}
