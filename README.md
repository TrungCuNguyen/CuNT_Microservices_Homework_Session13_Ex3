# Identity Service - Hệ Thống Microservices (Session 13)

Dự án triển khai **Identity Service** ("Phòng quản lý nhân khẩu" trong hệ thống Microservices), đảm nhiệm ba vai trò kỹ thuật quan trọng:
1. **Bài 1**: Đăng ký và lưu trữ tài khoản người dùng an toàn với mật khẩu băm BCrypt trong PostgreSQL.
2. **Bài 2**: Phát hành "tấm thẻ" (JWT Token) chứa thông tin `sub` (username) và `role` để người dùng xác thực với các service khác trong hệ thống Microservices.
3. **Bài 3**: API Đăng nhập (`POST /api/auth/login`), kiến trúc Stateless (không lưu Session/JSESSIONID), đối soát mật khẩu an toàn bằng `passwordEncoder.matches()` và phản hồi `401 Bad credentials` khi thông tin không khớp.

---

## 1. Cấu Trúc Dự Án

```
ex_ss13_micro/
├── .gitignore                      # Chỉ commit source code & cấu hình cần thiết
├── docker-compose.yml              # Khởi chạy PostgreSQL (identity_db) độc lập
├── settings.gradle                 # Quản lý module identity-service
├── gradlew / gradlew.bat           # Gradle Wrapper
├── requests.http                   # File test API sẵn sàng cho VS Code / IntelliJ
├── README.md                       # Tài liệu hướng dẫn chi tiết
└── identity-service/
    ├── build.gradle                # Khai báo dependencies Spring Boot, Security, JPA, JJWT, PostgreSQL
    └── src/
        ├── main/
        │   ├── java/com/example/identityservice/
        │   │   ├── IdentityServiceApplication.java
        │   │   ├── config/
        │   │   │   └── SecurityConfig.java         # Stateless Session & permitAll auth endpoints
        │   │   ├── controller/
        │   │   │   └── AuthController.java         # /register, /login, /test-token
        │   │   ├── dto/
        │   │   │   ├── RegisterRequest.java        # Request đăng ký
        │   │   │   ├── LoginRequest.java           # Request đăng nhập (username, password)
        │   │   │   ├── LoginResponse.java          # Response đăng nhập (accessToken, tokenType Bearer)
        │   │   │   └── UserResponse.java           # Response không chứa password
        │   │   ├── entity/
        │   │   │   └── User.java                   # Entity User (id UUID, username, password, role)
        │   │   ├── exception/
        │   │   │   ├── DuplicateResourceException.java
        │   │   │   ├── ResourceNotFoundException.java
        │   │   │   └── GlobalExceptionHandler.java # Xử lý 401 Bad credentials, 404, 409, 400
        │   │   ├── repository/
        │   │   │   └── UserRepository.java
        │   │   ├── service/
        │   │   │   ├── UserService.java
        │   │   │   └── impl/UserServiceImpl.java   # BCrypt.matches() & cấp phát JWT khi login
        │   │   └── util/
        │   │       └── JwtUtil.java                # Tạo & giải mã JWT Token (HS256, claim sub, claim role)
        │   └── resources/
        │       └── application.yml                 # Cấu hình PostgreSQL (identity_db) & jwt-secret / expiration
        └── test/
            └── java/com/example/identityservice/
                ├── IdentityServiceApplicationTests.java
                ├── controller/
                │   ├── AuthControllerTest.java     # Test controller endpoints (/register, /login, /test-token)
                │   └── RegisterIntegrationTest.java# Test End-to-End đầy đủ luồng Register & Login
                ├── service/
                │   └── UserServiceTest.java        # Test Unit logic băm mật khẩu, đăng nhập & cấp token
                └── util/
                    └── JwtUtilTest.java            # Test sinh token, claim sub, custom claim role, TTL
```

---

## 2. Thư Viện (Dependencies)

Trong [identity-service/build.gradle](identity-service/build.gradle):

- `org.springframework.boot:spring-boot-starter-data-jpa`: Tương tác cơ sở dữ liệu qua Hibernate/JPA.
- `org.springframework.boot:spring-boot-starter-security`: Bảo mật và mã hóa BCrypt.
- `org.springframework.boot:spring-boot-starter-web`: Xây dựng REST API.
- `org.springframework.boot:spring-boot-starter-validation`: Validate dữ liệu đầu vào.
- `io.jsonwebtoken:jjwt-api:0.11.5`: Thư viện tạo và xử lý JSON Web Token (JWT).
- `io.jsonwebtoken:jjwt-impl:0.11.5` & `io.jsonwebtoken:jjwt-jackson:0.11.5`: Runtime implementation và JSON Jackson parser cho JJWT.
- `org.postgresql:postgresql` (runtimeOnly): Driver kết nối PostgreSQL.

---

## 3. Cấu Hình Hệ Thống (`application.yml`)

```yaml
server:
  port: 8080

spring:
  application:
    name: identity-service
  datasource:
    url: jdbc:postgresql://localhost:5432/identity_db
    username: postgres
    password: ${POSTGRES_PASSWORD:17111998}
    driver-class-name: org.postgresql.Driver
  jpa:
    hibernate:
      ddl-auto: update

jwt:
  secret: 404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970 # Khóa bí mật 256-bit
  expiration: 3600000 # 3600000ms = 1 giờ
```

---

## 4. Chi Tiết Triển Khai Kỹ Thuật

### 4.1. Kiến trúc Stateless (`SecurityConfig.java`)
- **Vô hiệu hóa Session**: `SessionCreationPolicy.STATELESS` đảm bảo hệ thống không tạo `HttpSession` hay trả về header `Set-Cookie: JSESSIONID`. Mỗi request hoàn toàn độc lập.
- **Tắt CSRF**: `.csrf(AbstractHttpConfigurer::disable)`.
- **Public Endpoints**: Cho phép truy cập công khai vào `/api/auth/register`, `/api/auth/login`, `/api/auth/test-token`.

### 4.2. Logic Xác Thực Đăng Nhập (`UserServiceImpl.java`)
- **Bảo mật mật khẩu**: Tuyệt đối không dùng `==` hay `.equals()`, bắt buộc dùng:
  ```java
  passwordEncoder.matches(request.getPassword(), user.getPassword())
  ```
- **Thông báo lỗi chung**: Nếu không tìm thấy người dùng HOẶC mật khẩu không khớp, đều ném ngoại lệ `BadCredentialsException("Bad credentials")` để tránh lộ thông tin tài khoản cho kẻ tấn công (enumeration attack).
- **Mã phản hồi**:
  - Đăng nhập đúng: HTTP `200 OK` kèm `accessToken` và `tokenType: Bearer`.
  - Đăng nhập sai: HTTP `401 Unauthorized` kèm message `Bad credentials`.

### 4.3. API Endpoints

| Method | Endpoint | Mô tả | Yêu cầu kết quả |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Đăng ký người dùng | HTTP 201 Created (trả về user không có password, lưu hash BCrypt vào DB) |
| `POST` | `/api/auth/login` | Đăng nhập tài khoản | HTTP 200 OK kèm JWT token (hoặc 401 Unauthorized nếu sai) |
| `GET` | `/api/auth/test-token?username={name}` | Sinh JWT Token trực tiếp | HTTP 200 OK chuỗi JWT (hoặc 404 nếu không thấy user) |

---

## 5. Hướng Dẫn Chạy & Kiểm Thử

### Khởi chạy ứng dụng:
```powershell
.\gradlew.bat :identity-service:bootRun
```

### Chạy toàn bộ Test tự động (100% PASS):
```powershell
.\gradlew.bat :identity-service:test
```

### Kiểm tra bằng `requests.http` hoặc Postman:
1. **Đăng nhập đúng**:
   ```http
   POST http://localhost:8080/api/auth/login
   Content-Type: application/json

   {
     "username": "user_demo",
     "password": "Password123@"
   }
   ```
   **Phản hồi (200 OK)**:
   ```json
   {
     "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
     "tokenType": "Bearer"
   }
   ```

2. **Đăng nhập sai mật khẩu**:
   ```http
   POST http://localhost:8080/api/auth/login
   Content-Type: application/json

   {
     "username": "user_demo",
     "password": "WrongPassword@"
   }
   ```
   **Phản hồi (401 Unauthorized)**:
   ```json
   {
     "status": 401,
     "error": "Unauthorized",
     "message": "Bad credentials"
   }
   ```
