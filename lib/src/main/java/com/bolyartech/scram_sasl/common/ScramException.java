package com.bolyartech.scram_sasl.common;

/**
 * Indicates error while processing SCRAM sequence
 */
@SuppressWarnings("unused")
public class ScramException extends Exception {
    /**
     * Creates new ScramException
     * @param message Exception message
     */
    public ScramException(String message) {
        super(message);
    }


    /**
     * Creates new ScramException
     * @param cause Throwable
     */
    public ScramException(Throwable cause) {
        super(cause);
    }
}
