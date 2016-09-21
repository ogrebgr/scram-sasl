package com.bolyartech.scram_sasl.server;


import com.bolyartech.scram_sasl.common.SaslScramException;


public interface ScramSaslServerProcessor {
    void onMessage(String message) throws SaslScramException;

    void onUserDataLoaded(UserData data);

    void abort();

    long getConnectionId();

    boolean isEnded();

    boolean isSuccess();

    boolean isAborted();

    class UserData {
        public final String salt;
        public final int iterations;
        public final String serverKey;
        public final String storedKey;


        public UserData(String salt, int iterations, String serverKey, String storedKey) {
            this.salt = salt;
            this.iterations = iterations;
            this.serverKey = serverKey;
            this.storedKey = storedKey;
        }
    }


    interface UserDataLoader {
        void loadUserData(String username, long connectionId, ScramSaslServerProcessor interested);
    }


    interface Listener {
        void onSuccess(long connectionId);

        void onFailure(long connectionId);
    }


    interface Sender {
        void sendMessage(long connectionId, String msg);
    }
}
