package com.bolyartech.scram_sasl.server;


import com.bolyartech.scram_sasl.common.SaslScramException;


/**
 * Provides server side processing of the SCRAM SASL authentication
 */
@SuppressWarnings("unused")
public interface ScramSaslServerProcessor {
    /**
     * Called when there is message from the client
     * @param message Message
     * @throws SaslScramException if there is a unrecoverable problem during processing
     */
    void onMessage(String message) throws SaslScramException;

    /**
     * Called when {@link UserData} is loaded by {@link UserDataLoader}
     * @param data User data
     */
    void onUserDataLoaded(UserData data);

    /**
     * Aborts the procedure
     */
    void abort();

    /**
     * Client connection's ID
     * @return connection ID
     */
    long getConnectionId();

    /**
     * Checks if authentication sequence has ended
     * @return true if authentication has ended, false otherwise
     */
    boolean isEnded();

    /**
     * Checks if authentication sequence has ended successfully (i.e. user is authenticated)
     * @return true if authentication sequence has ended successfully, false otherwise
     */
    boolean isSuccess();

    /**
     * Checks if the sequence has been aborted
     * @return true if aborted, false otherwise
     */
    boolean isAborted();


    /**
     * Returns the authorized username (you must ensure that procedure is completed and successful before calling
     * this method)
     * @return Username of authorized user
     */
    String getAuthorizationID();

    /**
     * Wrapper for user data needed for the SCRAM authentication
     */
    @SuppressWarnings("unused")
    class UserData {
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


    /**
     * Loads user data
     * Implementations will usually load the user data from a DB
     */
    interface UserDataLoader {
        /**
         * Called when user data is loaded
         * @param username Username
         * @param connectionId ID of the connection
         * @param processor The client SCRAM processor
         */
        void loadUserData(String username, long connectionId, ScramSaslServerProcessor processor);
    }

    /**
     * Listener for success or failure of the SCRAM SASL authentication
     */
    interface Listener {
        /**
         * Called if the authentication completed successfully
         * @param connectionId ID of the connection
         */
        void onSuccess(long connectionId);
        /**
         * Called if the authentication failed
         * @param connectionId ID of the connection
         */
        void onFailure(long connectionId);
    }


    /**
     * Provides functionality for sending message to the client
     */
    interface Sender {
        /**
         * Sends message to the client identified by connectionId
         * @param connectionId ID of the client connection
         * @param msg Message
         */
        void sendMessage(long connectionId, String msg);
    }
}
