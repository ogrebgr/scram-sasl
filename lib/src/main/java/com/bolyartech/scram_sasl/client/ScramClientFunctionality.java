package com.bolyartech.scram_sasl.client;

import com.bolyartech.scram_sasl.common.ScramException;


/**
 * Provides building blocks for creating SCRAM authentication client
 *
 */
@SuppressWarnings("unused")
public interface ScramClientFunctionality {
    /**
     * Prepares the first client message
     * @param username Username of the user
     * @return First client message
     * @throws ScramException if username contains prohibited characters
     */
    String prepareFirstMessage(String username) throws ScramException;

    /**
     * Prepares client's final message
     * @param password User password
     * @param serverFirstMessage Server's first message
     * @return Client's final message
     * @throws ScramException if there is an error processing server's message, i.e. it violates the protocol
     */
    String prepareFinalMessage(String password, String serverFirstMessage) throws ScramException;

    /**
     * Checks if the server's final message is valid
     * @param serverFinalMessage Server's final message
     * @return true if the server's message is valid, false otherwise
     */
    boolean checkServerFinalMessage(String serverFinalMessage);

    /**
     * Checks if authentication is successful.
     * You can call this method only if authentication is completed. Ensure that using {@link #isEnded()}
     * @return true if successful, false otherwise
     */
    boolean isSuccessful();

    /**
     * Checks if authentication is completed, either successfully or not.
     * Authentication is completed if {@link #getState()} returns ENDED.
     * @return true if authentication has ended
     */
    boolean isEnded();

    /**
     * Gets the state of the authentication procedure
     * @return Current state
     */
    State getState();

    /**
     * State of the authentication procedure
     */
    enum State {
        /**
         * Initial state
         */
        INITIAL,
        /**
         * State after first message is prepared
         */
        FIRST_PREPARED,
        /**
         * State after final message is prepared
         */
        FINAL_PREPARED,
        /**
         * Authentication is completes, either successfully or not
         */
        ENDED
    }
}
