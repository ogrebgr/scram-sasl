package com.bolyartech.scram_sasl.server;

/**
 * Wrapper for user data needed for the SCRAM authentication
 */
public class UserData {
    /**
     * Salt
     */
    public final String salt;
    /**
     * Iterations used to salt the password
     */
    public final int iterations;
    /**
     * Server key
     */
    public final String serverKey;
    /**
     * Stored key
     */
    public final String storedKey;


    /**
     * Creates new UserData
     * @param salt Salt
     * @param iterations Iterations for salting
     * @param serverKey Server key
     * @param storedKey Stored key
     */
    public UserData(String salt, int iterations, String serverKey, String storedKey) {
        this.salt = salt;
        this.iterations = iterations;
        this.serverKey = serverKey;
        this.storedKey = storedKey;
    }
}
