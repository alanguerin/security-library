package com.submersive.common.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides convenient access a class logger.
 */
public interface Loggable {
    
    default Logger getLogger() {
        return LoggerFactory.getLogger(getClass());
    }
    
}

