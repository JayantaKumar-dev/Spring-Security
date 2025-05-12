# 🛡️ Spring Security Implementation Guide

## 🌟 Core Features

### 1️⃣ Authentication & Authorization
- **Authentication**: Verifies user identity (username/password, JWT)
- **Authorization**: Controls access to resources (URLs, methods)

### 🛡️ Protection Against Common Threats

#### 🔐 CSRF (Cross-Site Request Forgery)
```mermaid
sequenceDiagram
    User->>Browser: Logs into yourbank.com
    Attacker->>User: Sends malicious link
    Browser->>yourbank.com: Auto-executes request
    yourbank.com-->>Browser: Processes unintended action
Spring Security Solution:

java
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
)
🔒 Session Fixation
Attack Flow:

Attacker sets session ID: jsessionid=abc123

User logs in with same session

Attacker hijacks authenticated session

Protection:

java
http.sessionManagement(session -> session
    .sessionFixation().migrateSession()  // Default behavior
)
🕵️‍♂️ Clickjacking
Defense:

java
http.headers(headers -> headers
    .frameOptions().sameOrigin()
)
💣 Brute Force Attacks
Countermeasures:

java
// In your authentication configuration
http.authenticationProvider(authenticationProvider)
    .sessionManagement(session -> session
        .maximumSessions(1)
        .maxSessionsPreventsLogin(true)
    )
🏗️ Implementation Examples
Basic Configuration
java
@Configuration
@EnableWebSecurity
public class AppSecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
🔑 JWT Implementation
Token Generation
java
public String generateToken(String username, String role) {
    return JWT.create()
        .withSubject(username)
        .withClaim("role", role)
        .withExpiresAt(new Date(System.currentTimeMillis() + 86400000))
        .sign(Algorithm.HMAC256("secret-key"));
}
JWT Filter
java
@Component
public class JwtFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwt = authHeader.substring(7);
            // Token validation logic...
        }
        filterChain.doFilter(request, response);
    }
}
👨‍💻 User Registration Flow
Entity Structure
java
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String username;
    
    @Column(nullable = false)
    private String password;
    
    private String role;
    // Getters and setters...
}
Registration Service
java
@Service
public class AuthService {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    public APIResponse<String> register(UserDto dto) {
        if (userRepository.existsByUsername(dto.getUsername())) {
            return new APIResponse<>("Username exists", 400, null);
        }
        
        User user = new User();
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        // Set other fields...
        
        userRepository.save(user);
        return new APIResponse<>("Registration success", 201, null);
    }
}
🔐 Role-Based Access Control
Security Configuration
java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .requestMatchers("/user/**").hasAnyRole("ADMIN", "USER")
            .anyRequest().authenticated()
        )
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
}
UserDetailsService Implementation
java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username);
        return new org.springframework.security.core.userdetails.User(
            user.getUsername(),
            user.getPassword(),
            Collections.singleton(new SimpleGrantedAuthority(user.getRole()))
        );
    }
}
📚 Swagger Integration
xml
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
    <version>2.5.0</version>
</dependency>
Access Swagger UI:
http://localhost:8080/swagger-ui.html

🚀 Testing Endpoints
Registration (POST)
http
POST /api/v1/auth/register
Content-Type: application/json

{
    "username": "testuser",
    "password": "securePassword123!",
    "email": "test@example.com",
    "role": "USER"
}
Login (POST)
http
POST /api/v1/auth/login
Content-Type: application/json

{
    "username": "testuser",
    "password": "securePassword123!"
}
Admin Endpoint (GET)
http
GET /api/v1/admin/dashboard
Authorization: Bearer <your-jwt-token>
🔧 Dependencies
xml
<!-- Spring Security -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<!-- JWT Support -->
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>4.4.0</version>
</dependency>
