package br.com.lucas.projeto.arquitetura.gateway.filters;

import java.security.Key;
import java.time.Instant;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import reactor.core.publisher.Mono;

@Component
@Order(0)
public class AuthenticationFilter implements GlobalFilter {

	private static final String AUTHORIZATION_HEADER = "Authorization";
	private static final long EXPIRATION_THRESHOLD_SECONDS = 300000;
	private static final long EXPIRATION_TIME_MS = 3600000;

	@Value("${jwt.secret.key}")
	private String SECRET_KEY;
	
	@Value("${env.domain.name}")
	private String domain;

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

		String authHeader = exchange.getRequest().getHeaders().getFirst(AUTHORIZATION_HEADER);

		System.out.println("adicionando o header dinamicamente");

		String path = exchange.getRequest().getURI().getPath();

		HttpHeaders headers = exchange.getRequest().getHeaders();
		String origin = headers.getOrigin();
		System.out.println("ORIGIN: " + origin);

		// Permite apenas domínios do tipo *.lucaslabs.com
		if (origin != null && (origin.endsWith(domain) || origin.contains("localhost"))) {
			exchange.getResponse().getHeaders().remove("Access-Control-Allow-Origin");
			exchange.getResponse().getHeaders().setAccessControlAllowOrigin(origin);
			exchange.getResponse().getHeaders().setAccessControlAllowCredentials(true);
			// Trate requisições OPTIONS para retornar a resposta diretamente
			if (HttpMethod.OPTIONS.matches(exchange.getRequest().getMethod().name())) {
				exchange.getResponse().setStatusCode(HttpStatus.OK);
				return exchange.getResponse().setComplete();
			}
		}

		if (authHeader != null) {
			if (!authHeader.startsWith("Bearer ")) {
				exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
				return exchange.getResponse().setComplete();
			}

			String token = authHeader.substring(7);

			boolean isValid;
			try {
				isValid = validateToken(token);
				if (!isValid) {
					exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
					return exchange.getResponse().setComplete();
				}
			} catch (Exception e) {
				exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
				return exchange.getResponse().setComplete();
			}

			if (isTokenExpiring(token)) {
				String newToken = refreshToken(token);
				exchange.getRequest().mutate().header(AUTHORIZATION_HEADER, "Bearer " + newToken).build();
				exchange.getResponse().getHeaders().set(AUTHORIZATION_HEADER, newToken);
			}

		} else {
			if (path.startsWith("/sso-api/auth/")) {
				return chain.filter(exchange);
			} else {
				exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
				return exchange.getResponse().setComplete();
			}

		}
		return chain.filter(exchange);

	}

	private String refreshToken(String token) {
		Claims claims = Jwts.parserBuilder().setSigningKey(new SecretKeySpec(SECRET_KEY.getBytes(), SignatureAlgorithm.HS256.getJcaName())).build().parseClaimsJws(token).getBody();

		Date newExpiration = new Date(System.currentTimeMillis() + EXPIRATION_TIME_MS);

		return Jwts.builder().setClaims(claims).setExpiration(newExpiration).signWith(buildSecretKey()).compact();
	}

	private boolean isTokenExpiring(String token) {
		Claims claims = Jwts.parserBuilder().setSigningKey(buildSecretKey()).build().parseClaimsJws(token).getBody();

		Date expiration = claims.getExpiration();
		Instant now = Instant.now();

		return expiration.toInstant().isBefore(now.plusSeconds(EXPIRATION_THRESHOLD_SECONDS));
	}

	private boolean validateToken(String token) throws Exception {

		try {
			String username = Jwts.parserBuilder().setSigningKey(buildSecretKey()).build().parseClaimsJws(token).getBody().getSubject();

			return username != null;

		} catch (Exception e) {
			throw new Exception("Token inválido");
		}

	}

	private Key buildSecretKey() {

		return new SecretKeySpec(SECRET_KEY.getBytes(), SignatureAlgorithm.HS256.getJcaName());

	}

}
