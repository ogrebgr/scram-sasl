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
