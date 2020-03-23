package com.submersive.security.autoconfigure;

import com.submersive.security.config.SecurityProperties;
import com.submersive.security.filter.PreAuthenticatedAuthenticationFilter;
import lombok.AllArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@AllArgsConstructor
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
@ConditionalOnProperty(prefix = "submersive.security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SecurityAutoConfiguration extends WebSecurityConfigurerAdapter {
    
    private final SecurityProperties securityProperties;

    /**
     * Defines a {@link UserDetailsService} to create an underlying 'user' for an authenticated principal from a
     * pre-authenticated authentication request.
     */
    @Bean
    public AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService() {
        return new PreAuthenticatedGrantedAuthoritiesUserDetailsService();
    }

    /**
     * Defines an {@link AuthenticationProvider} to process pre-authenticated authentication requests.
     */
    @Bean
    public AuthenticationProvider preAuthenticatedAuthenticationProvider() {
        PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(authenticationUserDetailsService());
        return authenticationProvider;
    }

    /**
     * Prepares a Security filter to pre-authenticate an authenticated principal based on a provided identity token.
     * All principals authenticated through this filter will have the ROLE_USER authority.
     */
    @Bean
    public PreAuthenticatedAuthenticationFilter preAuthenticatedAuthenticationFilter() {
        return new PreAuthenticatedAuthenticationFilter(preAuthenticatedAuthenticationProvider(), securityProperties);
    }
    
    /**
     * Prepares a Security filter to authenticate an anonymous principal.
     * All principals authenticated through this filter will have the ROLE_ANONYMOUS authority.
     */
    @Bean
    public AnonymousAuthenticationFilter anonymousAuthenticationFilter() {
        return new AnonymousAuthenticationFilter(securityProperties.getClientKey());
    }
    
    /**
     * Create a security filter chain to introduce default request authorisation.
     * Applications inheriting this security filter chain will need to create a new security filter chain to override
     * this behaviour.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .sessionManagement().sessionCreationPolicy(STATELESS)
            .and()
            .csrf().disable()
            .exceptionHandling()
            .and()
            .addFilterAfter(preAuthenticatedAuthenticationFilter(), BasicAuthenticationFilter.class)
            .addFilterAfter(anonymousAuthenticationFilter(), PreAuthenticatedAuthenticationFilter.class)
            .authorizeRequests()
                .antMatchers("/actuator/**").permitAll() // Permit Spring Actuator
                .anyRequest().hasAnyAuthority("ROLE_USER", "ROLE_ANONYMOUS"); // Requests require a granted authority.
    }
    
}
