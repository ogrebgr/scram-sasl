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


/**
 * Provides client side processing of the SCRAM-SHA512 SASL authentication
 */
@SuppressWarnings("unused")
public class ScramSha512SaslClientProcessor extends AbstractScramSaslClientProcessor {
    /**
     * Creates new ScramSha512SaslClientProcessor
     * @param listener Listener of the client processor (this object)
     * @param sender Sender used to send messages to the server
     */
    public ScramSha512SaslClientProcessor(ScramSaslClientProcessor.Listener listener, ScramSaslClientProcessor.Sender sender) {
        super(listener, sender, "SHA-512", "HmacSHA512");
    }
}
