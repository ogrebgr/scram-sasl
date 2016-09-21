package com.bolyartech.scram_sasl.client;

public class ScramSha1SaslClientProcessor extends AbstractScramSaslClientProcessor {
    public ScramSha1SaslClientProcessor(Listener listener, Sender sender) {
        super(listener, sender, "SHA-1", "HmacSHA1");
    }
}
