package com.submersive.security.autoconfigure;

import lombok.AllArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
@ConditionalOnProperty(prefix = "submersive.security", name = "enabled", havingValue = "false")
public class DisableSecurityAutoConfiguration extends WebSecurityConfigurerAdapter {
    
    /**
     * Disable default Spring Security configuration.
     */
    @Override
    public void configure(WebSecurity web) {
        web.ignoring().anyRequest();
    }
    
}
