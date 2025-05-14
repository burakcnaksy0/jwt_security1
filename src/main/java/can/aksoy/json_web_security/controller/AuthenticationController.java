package can.aksoy.json_web_security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import can.aksoy.json_web_security.dto.UserRegister;
import can.aksoy.json_web_security.dto.UserRequest;
import can.aksoy.json_web_security.dto.UserResponse;
import can.aksoy.json_web_security.service.AuthenticationService;
import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/login")
@AllArgsConstructor
public class AuthenticationController {

	private final AuthenticationService authenticationService;
	
	@PostMapping("/register")
	public ResponseEntity<UserResponse> register(@RequestBody UserRegister userRegister){
		return ResponseEntity.ok(authenticationService.register(userRegister));
	}
	
	@PostMapping("/auth")
	public ResponseEntity<UserResponse> auth(@RequestBody UserRequest userRequest){
		return ResponseEntity.ok(authenticationService.auth(userRequest));
	}
}
