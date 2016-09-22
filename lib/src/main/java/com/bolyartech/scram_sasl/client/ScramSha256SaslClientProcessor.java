package com.bolyartech.scram_sasl.client;

/**
 * Provides client side processing of the SCRAM-SHA256 SASL authentication
 */
@SuppressWarnings("unused")
public class ScramSha256SaslClientProcessor extends AbstractScramSaslClientProcessor {
    /**
     * Creates new ScramSha256SaslClientProcessor
     * @param listener Listener of the client processor (this object)
     * @param sender Sender used to send messages to the server
     */
    public ScramSha256SaslClientProcessor(ScramSaslClientProcessor.Listener listener, ScramSaslClientProcessor.Sender sender) {
        super(listener, sender, "SHA-256", "HmacSHA256");
    }
}
