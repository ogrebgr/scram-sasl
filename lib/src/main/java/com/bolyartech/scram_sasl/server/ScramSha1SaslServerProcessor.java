package com.bolyartech.scram_sasl.server;



public class ScramSha1SaslServerProcessor extends AbstractScramSaslServerProcessor {
    public ScramSha1SaslServerProcessor(long connectionId,
                                        Listener listener,
                                        UserDataLoader userDataLoader,
                                        Sender sender) {

        super(connectionId, listener, userDataLoader, sender, "SHA-1", "HmacSHA1");
    }
}
