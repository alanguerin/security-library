package com.submersive.security.filter;

import com.submersive.common.logging.Loggable;
import com.submersive.security.config.SecurityProperties;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.isNull;

/**
 * Authenticate an anonymous request.
 * 
 * This filter will only be invoked after other authentication security filters, ensuring that there is an
 * {@link Authentication} object within the {@link SecurityContext}.
 */
@AllArgsConstructor
public class AnonymousAuthenticationFilter extends OncePerRequestFilter implements Loggable {
    
    private static final String DEFAULT_ROLE = "ROLE_ANONYMOUS";
    
    private final AuthenticationProvider authenticationProvider;
    private final SecurityProperties securityProperties;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        // Authenticate anonymously if there is no Authentication object or if it is not authenticated.
        if (isNull(authentication) || !authentication.isAuthenticated()) {
            authenticate();
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Authenticate an {@link AnonymousAuthenticationToken}.
     */
    private void authenticate() {
        String principal = UUID.randomUUID().toString();
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(DEFAULT_ROLE));
        
        AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(
            securityProperties.getClientKey(), principal, authorities
        );
        
        Authentication authentication = authenticationProvider.authenticate(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        getLogger().info("Anonymous authentication success. [principal={}]", authentication.getPrincipal());
    }
    
}
