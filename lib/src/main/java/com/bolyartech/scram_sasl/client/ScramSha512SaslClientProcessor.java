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
