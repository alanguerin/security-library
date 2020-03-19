package com.submersive.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Properties for our security library.
 */
@Getter
@Setter
@Configuration
public class SecurityProperties {

    /**
     * The client key used to issue anonymous tokens.
     */
    @Value("${submersive.security.token.clientKey:submersive}")
    private String clientKey;
    
    /**
     * Identifies the issuer of the token.
     */
    @Value("${submersive.security.token.issuer}")
    private String issuer;
    
    /**
     * The secret used to digitally sign the token so that it is trusted.
     */
    @Value("${submersive.security.token.secret}")
    private String secret;
    
}
