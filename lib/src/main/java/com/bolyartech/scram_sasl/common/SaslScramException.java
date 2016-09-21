package com.bolyartech.scram_sasl.common;

public class SaslScramException extends Exception {
    public SaslScramException(String message) {
        super(message);
    }


    public SaslScramException(Throwable cause) {
        super(cause);
    }
}
