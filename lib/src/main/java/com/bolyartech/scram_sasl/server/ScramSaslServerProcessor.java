/*
 * Copyright 2016 Ognyan Bankov
 * <p>
 * All rights reserved. Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.bolyartech.scram_sasl.server;

import com.bolyartech.scram_sasl.common.ScramException;


/**
 * Provides server side processing of the SCRAM SASL authentication
 */
@SuppressWarnings("unused")
public interface ScramSaslServerProcessor {
    /**
     * Called when there is message from the client
     *
     * @param message Message
     * @throws ScramException if there is a unrecoverable problem during processing
     */
    void onMessage(String message) throws ScramException;

    /**
     * Called when {@link UserData} is loaded by {@link UserDataLoader}
     *
     * @param data User data
     */
    void onUserDataLoaded(UserData data);

    /**
     * Aborts the procedure
     */
    void abort();

    /**
     * Client connection's ID
     *
     * @return connection ID
     */
    long getConnectionId();

    /**
     * Checks if authentication sequence has ended
     *
     * @return true if authentication has ended, false otherwise
     */
    boolean isEnded();

    /**
     * Checks if authentication sequence has ended successfully (i.e. user is authenticated)
     *
     * @return true if authentication sequence has ended successfully, false otherwise
     */
    boolean isSuccess();

    /**
     * Checks if the sequence has been aborted
     *
     * @return true if aborted, false otherwise
     */
    boolean isAborted();


    /**
     * Returns the authorized username (you must ensure that procedure is completed and successful before calling
     * this method)
     *
     * @return Username of authorized user
     */
    String getAuthorizationID();


    /**
     * Loads user data
     * Implementations will usually load the user data from a DB
     */
    interface UserDataLoader {
        /**
         * Called when user data is loaded
         *
         * @param username     Username
         * @param connectionId ID of the connection
         * @param processor    The client SCRAM processor
         */
        void loadUserData(String username, long connectionId, ScramSaslServerProcessor processor);
    }

    /**
     * Listener for success or failure of the SCRAM SASL authentication
     */
    interface Listener {
        /**
         * Called if the authentication completed successfully
         *
         * @param connectionId ID of the connection
         */
        void onSuccess(long connectionId);

        /**
         * Called if the authentication failed
         *
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
         *
         * @param connectionId ID of the client connection
         * @param msg          Message
         */
        void sendMessage(long connectionId, String msg);
    }
}
