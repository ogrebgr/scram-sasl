package com.bolyartech.scram_sasl.client;


import com.bolyartech.scram_sasl.common.SaslScramException;
import com.bolyartech.scram_sasl.common.StringPrep;


public interface ScramSaslClientProcessor {
    void start(String username, String password) throws StringPrep.StringPrepError;
    void onMessage(String message) throws SaslScramException;
    void abort();

    boolean isEnded();
    boolean isSuccess();
    boolean isAborted();


    interface Listener {
        void onSuccess();

        void onFailure();
    }


    interface Sender {
        void sendMessage(String msg);
    }
}
