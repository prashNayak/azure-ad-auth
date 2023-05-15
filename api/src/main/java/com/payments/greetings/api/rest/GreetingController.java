
package com.payments.greetings.api.rest;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import com.auth0.jwt.interfaces.Claim;
import com.payments.greetings.api.token.Auth0Parser;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/v1")
@Slf4j
public class GreetingController {

    @PreAuthorize("hasAuthority('SCOPE_PAYMENTS')")
    @GetMapping("/hi")
    public String hi() {
        return "Hi";
    }

    @PreAuthorize("hasAuthority('SCOPE_CallHelloApiRole')")
    @GetMapping("/hello")
    public String hello(@RequestParam(name = "name", required = true)
    final String name) {
        return String.format("Hello, %s", name);
    }

    @GetMapping("/whoami")
    public String whoami(HttpServletRequest request) {

        // Get security context and print authorities
        SecurityContext securityContext = SecurityContextHolder.getContext();
        log.info("whoami: Full authentication securityContext.getAuthentication-> {}", securityContext.getAuthentication());
        securityContext.getAuthentication().getAuthorities().stream().forEach(
                (val) -> log.info("Authority->{}", val.getAuthority()));

        // Get token value from the header
        String authHeaderValue = request.getHeader("Authorization");
        log.debug("authHeaderValue: {}", authHeaderValue);

        String appId = "undefined";

        if (!StringUtils.isEmpty(authHeaderValue)) {
            String token = request.getHeader("Authorization").replaceAll("Bearer ", "");
            log.debug("token: {}", token);

            // Access all claims from the token itself by using Auth0 JWT impl
            Map <String, Claim> claims = new Auth0Parser().getClaims(token);
            if (!claims.isEmpty()) {
                claims.get("roles").asList(String.class).forEach(role -> log.info(role));
                appId = claims.get("appid").asString();
            }
        }

        return appId;

    }

    @GetMapping("/verify")
    public String verify(HttpServletRequest request) {
        String authHeaderValue = request.getHeader("Authorization");
        System.out.println( authHeaderValue);
        if (authHeaderValue != null){
            try {

                String token = authHeaderValue.substring(7, authHeaderValue.length());
                DecodedJWT jwt = JWT.decode(token);
                URI uri = (new URI("https://login.microsoftonline.com/common/discovery/v2.0/keys")).normalize();
                JwkProvider provider = new UrlJwkProvider(uri.toURL());
                Jwk jwk = provider.get(jwt.getKeyId());
                Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
                algorithm.verify(jwt);



                Map <String, Claim> claims = jwt.getClaims();
                System.out.println("Application ID" + claims.get("appid").asString());

                List<String> rolesList = claims.get("roles").asList(String.class);
                System.out.println("List of roles application has : " + rolesList);


                // Check expiration
                if (jwt.getExpiresAt().before(Calendar.getInstance().getTime())) {

                    return "Token expired";
                }

            }catch(Exception e){
                System.out.println("Problem with verifying the AD access token");
                System.out.println(e);
            }
        }
       return "Token valid";
    }
}