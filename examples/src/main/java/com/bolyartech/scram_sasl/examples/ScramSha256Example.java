package com.bolyartech.scram_sasl.examples;

import com.bolyartech.scram_sasl.client.ScramSaslClientProcessor;
import com.bolyartech.scram_sasl.client.ScramSha256SaslClientProcessor;
import com.bolyartech.scram_sasl.common.ScramException;
import com.bolyartech.scram_sasl.common.ScramUtils;
import com.bolyartech.scram_sasl.server.ScramSaslServerProcessor;
import com.bolyartech.scram_sasl.server.ScramSha256SaslServerProcessor;
import com.bolyartech.scram_sasl.server.UserData;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


public class ScramSha256Example {

    /**
     * Shows how to use both client and server with SCRAM SHA-256
     */
    public static void main(String[] args) {
        ScramSha256SaslServerProcessor.Listener serverListener = new ScramSha256SaslServerProcessor.Listener() {

            @Override
            public void onSuccess(long connectionId) {
                System.out.println("Server success");
            }


            @Override
            public void onFailure(long connectionId) {
                System.out.println("Server fail");
            }
        };


        ScramSaslClientProcessor.Listener clientListener = new ScramSaslClientProcessor.Listener() {
            @Override
            public void onSuccess() {
                System.out.println("Client success");
            }


            @Override
            public void onFailure() {
                System.out.println("Client fail");
            }
        };


        @SuppressWarnings("Convert2Lambda")
        ScramSaslServerProcessor.UserDataLoader loader = new ScramSaslServerProcessor.UserDataLoader() {
            @Override
            public void loadUserData(String username, long connectionId, ScramSaslServerProcessor processor) {
                // we fake the loading by simply generating new user data
                SecureRandom random = new SecureRandom();
                byte[] salt = new byte[24];
                random.nextBytes(salt);


                try {
                    ScramUtils.NewPasswordStringData data = ScramUtils.byteArrayToStringData(
                            ScramUtils.newPassword("ogre1234", salt, 4096, "SHA-256", "HmacSHA256")
                    );

                    // we notify the processor
                    processor.onUserDataLoaded(
                            new UserData(data.salt,
                                    data.iterations,
                                    data.serverKey,
                                    data.storedKey));

                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    e.printStackTrace();
                }
            }
        };

        MyToServerSender toServerSender = new MyToServerSender();
        ScramSha256SaslClientProcessor client = new ScramSha256SaslClientProcessor(clientListener, toServerSender);

        MyToClientSender toClientSender = new MyToClientSender(client);
        ScramSha256SaslServerProcessor server = new ScramSha256SaslServerProcessor(1, serverListener, loader,
                toClientSender);

        toServerSender.setServer(server);

        try {
            client.start("ogre", "ogre1234");
        } catch (ScramException e) {
            e.printStackTrace();
        }

    }


    private static class MyToClientSender implements ScramSaslServerProcessor.Sender {
        private final ScramSaslClientProcessor client;


        public MyToClientSender(ScramSaslClientProcessor client) {
            this.client = client;
        }


        @Override
        public void sendMessage(long connectionId, String msg) {
            try {
                client.onMessage(msg);
            } catch (ScramException e) {
                e.printStackTrace();
            }
        }
    }


    private static class MyToServerSender implements ScramSaslClientProcessor.Sender {
        private ScramSaslServerProcessor mServer;


        @Override
        public void sendMessage(String msg) {
            try {
                mServer.onMessage(msg);
            } catch (ScramException e) {
                e.printStackTrace();
            }
        }


        public void setServer(ScramSaslServerProcessor server) {
            mServer = server;
        }
    }
}
