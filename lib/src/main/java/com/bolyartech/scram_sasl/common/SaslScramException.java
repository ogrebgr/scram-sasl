package com.bolyartech.scram_sasl.common;

/**
 * Indicates error while processing SCRAM sequence
 */
@SuppressWarnings("unused")
public class SaslScramException extends Exception {
    /**
     * Creates new SaslScramException
     * @param message Exception message
     */
    public SaslScramException(String message) {
        super(message);
    }


    /**
     * Creates new SaslScramException
     * @param cause Throwable
     */
    public SaslScramException(Throwable cause) {
        super(cause);
    }
}
