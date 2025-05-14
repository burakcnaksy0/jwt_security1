package can.aksoy.json_web_security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/dashboard")
public class DashboardController {

	@GetMapping
	public ResponseEntity<String> dashboard(){
		return ResponseEntity.ok("welcome dashboard.");
	}
}
