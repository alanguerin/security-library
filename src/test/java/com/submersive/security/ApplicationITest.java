package com.submersive.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(classes = TestApplication.class)
@ActiveProfiles("test")
public class ApplicationITest {
    
    @Test
    void testApplicationStart() {
        assertTrue(true);
    }
    
}
