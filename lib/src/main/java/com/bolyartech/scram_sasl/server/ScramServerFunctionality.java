package com.bolyartech.scram_sasl.server;

import com.bolyartech.scram_sasl.common.ScramException;


/**
 * Provides building blocks for creating SCRAM authentication server
 */
@SuppressWarnings("unused")
public interface ScramServerFunctionality {
    /**
     * Handles client's first message
     * @param message Client's first message
     * @return username extracted from the client message
     */
    String handleClientFirstMessage(String message);

    /**
     * Prepares server's first message
     * @param userData user data needed to prepare the message
     * @return Server's first message
     */
    String prepareFirstMessage(UserData userData);

    /**
     * Prepares server's final message
     * @param clientFinalMessage Client's final message
     * @return Server's final message
     * @throws ScramException if there is an error processing clients message
     */
    String prepareFinalMessage(String clientFinalMessage) throws ScramException;

    /**
     * Checks if authentication is completed, either successfully or not.
     * Authentication is completed if {@link #getState()} returns ENDED.
     * @return true if authentication has ended
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
         * First client message is handled (username is extracted)
         */
        FIRST_CLIENT_MESSAGE_HANDLED,
        /**
         * First server message is prepared
         */
        PREPARED_FIRST,
        /**
         * Authentication is completes, either successfully or not
         */
        ENDED
    }
}
