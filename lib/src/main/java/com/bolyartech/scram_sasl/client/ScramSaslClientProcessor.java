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

package com.bolyartech.scram_sasl.client;

import com.bolyartech.scram_sasl.common.ScramException;


/**
 * Provides client side processing of the SCRAM SASL authentication
 */
@SuppressWarnings("unused")
public interface ScramSaslClientProcessor {
    /**
     * Initiates the SCRAM sequence by preparing and sending the first client message
     * @param username username of the user
     * @param password password of the user
     * @throws ScramException if username contains forbidden characters (@see https://tools.ietf.org/html/rfc4013)
     */
    void start(String username, String password) throws ScramException;

    /**
     * Called when message from server is received
     * @param message Message
     * @throws ScramException if there is a unrecoverable error during internal processing of the message
     */
    void onMessage(String message) throws ScramException;

    /**
     * Aborts the procedure
     */
    void abort();
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
     * Listener for success or failure of the SCRAM SASL authentication
     */
    interface Listener {
        /**
         * Called if the authentication completed successfully
         */
        void onSuccess();

        /**
         * Called if the authentication failed
         */
        void onFailure();
    }


    /**
     * Provides functionality for sending message to the server
     */
    interface Sender {
        /**
         * Sends message to the server
         * @param msg Message
         */
        void sendMessage(String msg);
    }
}
