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


/**
 * Provides server side processing of the SCRAM-SHA256 SASL authentication
 */
@SuppressWarnings("unused")
public class ScramSha512SaslServerProcessor  extends AbstractScramSaslServerProcessor {
    /**
     * Creates new ScramSha512SaslServerProcessor
     * @param connectionId ID of the client connection
     * @param listener Listener
     * @param userDataLoader loader for user data
     * @param sender Sender used to send messages to the clients
     */
    public ScramSha512SaslServerProcessor(long connectionId,
                                          Listener listener,
                                          UserDataLoader userDataLoader,
                                          Sender sender) {

        super(connectionId, listener, userDataLoader, sender, "SHA-512", "HmacSHA512");
    }
}
