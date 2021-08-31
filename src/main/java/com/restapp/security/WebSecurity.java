package com.restapp.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, 
securedEnabled = true, 
jsr250Enabled = true)
public class WebSecurity extends WebSecurityConfigurerAdapter {
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
	 
	 
		http
		.authorizeRequests()
		.antMatchers(HttpMethod.GET, "/api/people")
		.hasAuthority("SCOPE_profile")
		.antMatchers(HttpMethod.GET, "/api/db/people")
		.hasRole("programmer")
		    .anyRequest().authenticated()
				.and()
			.oauth2ResourceServer()
			.jwt()
		    .jwtAuthenticationConverter(jwtAuthenticationConverter);
	}
	
}
