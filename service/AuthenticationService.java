

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ma.dto.LoginRequestDTO;
import com.ma.dto.LoginResponseDTO;
import com.ma.dto.RegisterRequestDTO;
import com.ma.entity.User;
import com.ma.jwt.JwtService;
import com.ma.repository.UserRepository;

@Service
public class AuthenticationService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    // ✅ Register Normal User
    public User registerNormalUser(RegisterRequestDTO registerRequestDTO) {
        if (userRepository.findByUsername(registerRequestDTO.getUsername()).isPresent()) {
            throw new RuntimeException("User already registered");
        }

        Set<String> roles = new HashSet<>();
        roles.add("ROLE_USER");

        User user = new User();
        user.setUsername(registerRequestDTO.getUsername());
        user.setEmail(registerRequestDTO.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequestDTO.getPassword()));
        user.setRoles(roles);

        return userRepository.save(user);
    }

    // ✅ Register Admin User
    public User registerAdminUser(RegisterRequestDTO registerRequestDTO) {
        if (userRepository.findByUsername(registerRequestDTO.getUsername()).isPresent()) {
            throw new RuntimeException("User already registered");
        }

        Set<String> roles = new HashSet<>();
        roles.add("ROLE_ADMIN");
        roles.add("ROLE_USER");

        User user = new User();
        user.setUsername(registerRequestDTO.getUsername());
        user.setEmail(registerRequestDTO.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequestDTO.getPassword()));
        user.setRoles(roles);

        return userRepository.save(user);
    }

    // ✅ Login User
    public LoginResponseDTO login(LoginRequestDTO loginRequestDTO) {
        // 1. Authenticate username/password
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequestDTO.getUsername(),
                        loginRequestDTO.getPassword()
                )
        );

        // 2. Fetch user
        User user = userRepository.findByUsername(loginRequestDTO.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 3. Generate JWT token
        String token = jwtService.generateToken(user);

        // 4. Return LoginResponse
        return LoginResponseDTO.builder()
                .jwtToken(token)
                .username(user.getUsername())
                .roles(user.getRoles())
                .build();
    }
}