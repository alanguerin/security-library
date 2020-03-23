package com.submersive.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.submersive.common.logging.Loggable;
import com.submersive.security.config.SecurityProperties;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthoritiesContainer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * Authenticate a pre-authenticated request.
 * 
 * This filter will attempt to authenticate the request based on an access token specified in the Authorization HTTP
 * header. The access token needs to be valid and complete for the authentication procedure to succeed. 
 * 
 * On success, an {@link Authentication} object will be added to the {@link SecurityContext}.
 */
@AllArgsConstructor
public class PreAuthenticatedAuthenticationFilter extends OncePerRequestFilter implements Loggable {
    
    private static final String DEFAULT_ROLE = "ROLE_USER";
    
    private final AuthenticationProvider authenticationProvider;
    private final SecurityProperties securityProperties;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (nonNull(SecurityContextHolder.getContext().getAuthentication())) {
            getLogger().debug("SecurityContextHolder not populated with a pre-authenticated token, as it already contained: {}",
                SecurityContextHolder.getContext().getAuthentication());

            filterChain.doFilter(request, response);
            return;
        }

        String token = request.getHeader(AUTHORIZATION);
        
        // If a token has not been provided, invoke the next filter in the chain. 
        if (isNull(token)) {
            getLogger().debug("A pre-authenticated token has not been provided, so there is nothing to authenticate.");
            filterChain.doFilter(request, response);
            return;
        }
        
        try {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC512(securityProperties.getSecret()))
                .withIssuer(securityProperties.getIssuer())
                .build();

            token = pruneAuthenticationScheme(token);
            
            DecodedJWT decodedToken = verifier.verify(token);
            getLogger().info("Token verified. [subject={}]", decodedToken.getSubject());
            
            authenticate(request, decodedToken);
            filterChain.doFilter(request, response);
        } catch (JWTVerificationException e) {
            getLogger().info("Token failed verification. [{}]", e.getMessage());
            
            // Continue along the security filter chain, as the provided token is unusable.
            filterChain.doFilter(request, response);
        }
    }

    /**
     * Prune the HTTP Authentication Scheme from the token.
     * This method doesn't verify the provided authentication scheme.
     */
    private String pruneAuthenticationScheme(String token) {
        return token.contains(" ") ? token.split(" ", 2)[1] : token;
    }
    
    /**
     * Authenticate a {@link PreAuthenticatedAuthenticationToken}.
     */
    private void authenticate(HttpServletRequest request, DecodedJWT decodedToken) {
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(DEFAULT_ROLE));
        GrantedAuthoritiesContainer authoritiesContainer = new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(request, authorities);
        
        PreAuthenticatedAuthenticationToken authenticationToken = new PreAuthenticatedAuthenticationToken(decodedToken.getSubject(), "N/A");
        authenticationToken.setDetails(authoritiesContainer);

        Authentication authentication = authenticationProvider.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        getLogger().info("Pre-authentication success. [principal={}]", ((User)authentication.getPrincipal()).getUsername());
    }
    
}
