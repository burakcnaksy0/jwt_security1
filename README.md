
# Spring Security + JWT Yapısı

Bu döküman, Spring Security ile JWT kullanılarak oluşturulan kimlik doğrulama sisteminin ana bileşenlerini açıklar.

---

## 🔐 AuthenticationManager
- Bir kullanıcının kimliğini doğrulamak için kullanılan arabirimdir.
- `Authentication` nesnesi alır.
- Bunu bir veya daha fazla `AuthenticationProvider`'a göndererek doğrulama yapar.
- Başarılıysa `Authentication` nesnesi döner.

```java
@Autowired
AuthenticationManager authenticationManager;

Authentication auth = authenticationManager.authenticate(
    new UsernamePasswordAuthenticationToken(username, password));
```

---

## 🔐 AuthenticationProvider
- Gerçek kimlik doğrulama işleminin yapıldığı yerdir.
- `supports()` metodu ile kendisine uygun `Authentication` nesnesini kontrol eder.
- `authenticate()` metodu ile kullanıcı adı ve şifreyi kontrol eder.
- Spring varsayılanı: `DaoAuthenticationProvider`

---

## 🧰 AuthenticationFilter (JWT için: `JwtAuthenticationFilter`)
- Spring Security Filter Chain'de gelen HTTP isteklerini yakalayarak, içindeki token veya giriş bilgilerini ayrıştıran filtredir.
- `/login` isteğini yakalar, username & password alır.
- JWT varsa header’dan çıkarır ve doğrulama için `AuthenticationManager`'a gönderir.

### 📎 Bağımlılıklar:
**1 - JwtService**  
JWT içindeki kullanıcı bilgilerini çözümlemek ve doğrulamak için kullanılır.

**Neden Gerekli?**  
- JWT içinden kullanıcı adını çıkarmak (`extractUsername`)
- Token’ın geçerliliğini kontrol etmek (`isTokenValid`)
```java
String jwt = authHeader.substring(7);
String username = jwtService.extractUsername(jwt);

if (jwtService.isTokenValid(jwt, userDetails)) {
    ...
}
```

**2 - CustomUserDetailsService**  
Token'dan alınan kullanıcı adına göre veritabanından kullanıcıyı yükler. `UserDetails` nesnesi döner.

**Neden Gerekli?**  
- Token manipüle edilmiş olabilir, bu yüzden JWT içeriğine doğrudan güvenemeyiz.
- Doğrulama için veritabanından kullanıcıyı yüklememiz gerekir.

```java
UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
```

```java
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(...) {
        // Authorization header’dan JWT çıkarılır
        // JwtService ile doğrulama yapılır
        // Kullanıcı SecurityContext'e yerleştirilir
    }
}
```

---

## 👤 UserDetailsService
- Kullanıcı bilgilerini veritabanından veya başka kaynaktan yükleyen bileşendir.
- `loadUserByUsername(username)` metodunu sağlar.
- Geriye `UserDetails` nesnesi döner.

```java
@Service
public class MyUserDetailsService implements UserDetailsService {
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username);
        return new MyUserDetails(user);
    }
}
```

---

## 👤 UserDetails
- Kullanıcının kimlik bilgilerini ve yetkilerini (rollerini) tutan bir arayüzdür.
- Kullanıcı adı, şifre, roller, hesap aktif mi gibi durumları içerir.

```java
public class MyUserDetails implements UserDetails {
    private User user;

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(user.getRole()));
    }

    public String getPassword() { return user.getPassword(); }
    public String getUsername() { return user.getUsername(); }
}
```

---

## 🛠️ JwtService
- JWT token üretme, çözümleme ve geçerlilik kontrolü yapan servistir.
- `generateToken(UserDetails)` → JWT oluşturur.
- `isTokenValid(token, userDetails)` → token geçerli mi kontrol eder.
- `extractUsername(token)` → JWT içinden username alır.

```java
public String generateToken(UserDetails userDetails) {
    return Jwts.builder()
        .setSubject(userDetails.getUsername())
        .setIssuedAt(...)
        .setExpiration(...)
        .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
        .compact();
}
```

---

## ⚙️ AuthenticationService
Login, register, logout gibi genel kullanıcı işlemlerini yönetir. Controller yerine servis mantığıyla çalışır.

### İşlevleri:
- Kullanıcıyı kaydet (`register`)
- Kimlik doğrula (`login`)
- JWT üret ve dön
- Refresh token işlemleri

### 📎 Bağımlılıklar:
**1 - UserRepository**  
Kullanıcıyı veritabanına kaydetmek ve giriş sırasında bulmak için.

**2 - PasswordEncoder**  
Şifreyi hash’lemek için kullanılır. Hashlenmemiş şifre veritabanına yazılmaz.

```java
passwordEncoder.encode(request.password());
```

**3 - JwtService**  
JWT token üretmek için kullanılır. `register()` ve `authenticate()` içinde `generateToken(user)` çağrılır.

**4 - AuthenticationManager**  
Kullanıcının gönderdiği username ve password’ü doğrulamak için kullanılır.

```java
Authentication auth = authenticationManager.authenticate(
    new UsernamePasswordAuthenticationToken(username, password));
```

```java
@Service
public class AuthenticationService {
    public AuthResponse login(LoginRequest request) {
        Authentication auth = authenticationManager.authenticate(...);
        var user = (User) auth.getPrincipal();
        var token = jwtService.generateToken(user);
        return new AuthResponse(token);
    }
}
```

---

## 🛡️ Spring Security Filter Chain
Tüm HTTP istekleri bu filtre zincirinden geçer.  
`UsernamePasswordAuthenticationFilter`, `JwtAuthenticationFilter`, `ExceptionTranslationFilter`, `SecurityContextPersistenceFilter` gibi filtreleri sıralı şekilde çalıştırır.

### 📎 Bağımlılıklar:
**1 - JwtAuthenticationFilter**  
JWT'yi HTTP isteklerinden okuyup, geçerliyse kullanıcıyı tanıtmak için kullanılır.

```java
.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
```

**2 - CustomUserDetailsService**  
Veritabanından kullanıcıyı username ile bulur.  
`AuthenticationProvider -> UserDetailsService` zincirinde kullanılır.

**3 - DaoAuthenticationProvider**  
`UserDetailsService` + `PasswordEncoder` ile kullanıcı doğrulaması yapar.

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
        .csrf().disable()
        .authorizeHttpRequests()
        .requestMatchers("/auth/**").permitAll()
        .anyRequest().authenticated()
        .and()
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
}
```

---

## 🧩 AuthController
- `AuthenticationService`’e bağımlıdır.
- `/register` ve `/login` işlemlerinin iş mantığını barındırır.
- Kullanıcı kaydı, parola hashleme, kullanıcı doğrulama, JWT token üretimi gibi işlevleri içerir.

**Amaç:**  
Güvenli kullanıcı doğrulaması ve token üretimi için servis katmanıyla çalışmaktır.
