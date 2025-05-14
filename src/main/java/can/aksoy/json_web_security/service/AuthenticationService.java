package can.aksoy.json_web_security.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import can.aksoy.json_web_security.dto.UserRegister;
import can.aksoy.json_web_security.dto.UserRequest;
import can.aksoy.json_web_security.dto.UserResponse;
import can.aksoy.json_web_security.entity.User;
import can.aksoy.json_web_security.enums.Role;
import can.aksoy.json_web_security.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@Service
@AllArgsConstructor
public class AuthenticationService {

	private final UserRepository userRepository;
	private final JwtService jwtService;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;

	public UserResponse register(UserRegister userRegister) {
		User user = User.builder().nameSurname(userRegister.getNameSurname()).username(userRegister.getUsername())
				.password(passwordEncoder.encode(userRegister.getPassword())).role(Role.USER).build();

		userRepository.save(user);

		var token = jwtService.generateToken(user);
		return UserResponse.builder().token(token).build();

	}

	public UserResponse auth(UserRequest userRequest) {
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(userRequest.getUsername(), userRequest.getPassword()));
		User user = userRepository.findByUsername(userRequest.getUsername()).orElseThrow();

		String token = jwtService.generateToken(user);

		return UserResponse.builder().token(token).build();

	}
}
