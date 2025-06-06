package can.aksoy.json_web_security.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	@Value("${security.jwt.secret}")
	private String SECRET_KEY;
	
	
	// token içindeki username değerini bulur.
	public String findUsername(String jwt) {
		return exportToken(jwt , Claims::getSubject);
	}

	// token çözümlemesi yapılır
	private <T> T exportToken(String jwt, Function<Claims, T> claimsFunction) {
		final Claims claims = Jwts.parserBuilder()
				.setSigningKey(getKey())
				.build()
				.parseClaimsJws(jwt)
				.getBody();
		return claimsFunction.apply(claims);
	}


	private Key getKey() {
		byte[] key = Decoders.BASE64.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(key);
	}
	
	// token geçerli mi değil mi kontrolü yapılır.
	public boolean tokenControl(String jwt , UserDetails userDetails) {
		final String username = findUsername(jwt);
		return (username.equals(userDetails.getUsername()) && !exportToken(jwt, Claims::getExpiration ).before(new Date()) );
	}
	
	// token üretmek için kullanılır.
	public String generateToken(UserDetails userDetails) {
		return Jwts.builder()
				.setClaims(new HashMap<>())
				.setSubject(userDetails.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000*60*24))
				.signWith(getKey() , SignatureAlgorithm.HS256)
				.compact();
	}
	
	
	
	
	
}
