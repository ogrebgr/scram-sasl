package com.bolyartech.scram_sasl.client;

/**
 * Provides client side processing of the SCRAM-SHA1 SASL authentication
 */
@SuppressWarnings("unused")
public class ScramSha1SaslClientProcessor extends AbstractScramSaslClientProcessor {
    /**
     * Creates new ScramSha1SaslClientProcessor
     * @param listener Listener of the client processor (this object)
     * @param sender Sender used to send messages to the server
     */
    public ScramSha1SaslClientProcessor(Listener listener, Sender sender) {
        super(listener, sender, "SHA-1", "HmacSHA1");
    }
}
