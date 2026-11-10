package com.example.identityservice.controller;

import com.example.identityservice.config.SecurityConfig;
import com.example.identityservice.dto.LoginRequest;
import com.example.identityservice.dto.LoginResponse;
import com.example.identityservice.dto.RegisterRequest;
import com.example.identityservice.dto.UserResponse;
import com.example.identityservice.exception.ResourceNotFoundException;
import com.example.identityservice.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserService userService;

    @Test
    @DisplayName("POST /api/auth/register should return 201 Created and user details without password")
    void register_Success() throws Exception {
        RegisterRequest request = new RegisterRequest("testuser", "securePassword123", "USER");
        UserResponse response = new UserResponse("123e4567-e89b-12d3-a456-426614174000", "testuser", "USER");

        when(userService.register(any(RegisterRequest.class))).thenReturn(response);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value("123e4567-e89b-12d3-a456-426614174000"))
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    @DisplayName("POST /api/auth/register should return 400 when username is blank")
    void register_InvalidUsername_ReturnsBadRequest() throws Exception {
        RegisterRequest request = new RegisterRequest("", "securePassword123", "USER");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("GET /api/auth/test-token should return 200 OK and JWT string")
    void getTestToken_Success() throws Exception {
        String mockJwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlciIsInJvbGUiOiJVU0VSIiwiZXhwIjoxNzMxMjUxNjAwfQ.testSignature";
        when(userService.generateTestToken("testuser")).thenReturn(mockJwt);

        mockMvc.perform(get("/api/auth/test-token")
                        .param("username", "testuser"))
                .andExpect(status().isOk())
                .andExpect(content().string(mockJwt));
    }

    @Test
    @DisplayName("GET /api/auth/test-token should return 404 when user is not found")
    void getTestToken_NotFound() throws Exception {
        when(userService.generateTestToken("notfound"))
                .thenThrow(new ResourceNotFoundException("User not found with username: notfound"));

        mockMvc.perform(get("/api/auth/test-token")
                        .param("username", "notfound"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("User not found with username: notfound"));
    }

    @Test
    @DisplayName("POST /api/auth/login should return 200 OK and accessToken on valid credentials")
    void login_Success() throws Exception {
        LoginRequest request = new LoginRequest("testuser", "securePassword123");
        LoginResponse response = new LoginResponse("mock.jwt.token", "Bearer");

        when(userService.login(any(LoginRequest.class))).thenReturn(response);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("mock.jwt.token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    @DisplayName("POST /api/auth/login should return 401 Unauthorized on invalid credentials")
    void login_InvalidCredentials_ReturnsUnauthorized() throws Exception {
        LoginRequest request = new LoginRequest("testuser", "wrongPassword");

        when(userService.login(any(LoginRequest.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Bad credentials"))
                .andExpect(jsonPath("$.status").value(401));
    }
}
