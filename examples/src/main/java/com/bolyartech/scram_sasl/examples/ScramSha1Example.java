package com.bolyartech.scram_sasl.examples;


import com.bolyartech.scram_sasl.client.ScramSaslClientProcessor;
import com.bolyartech.scram_sasl.client.ScramSha1SaslClientProcessor;
import com.bolyartech.scram_sasl.common.SaslScramException;
import com.bolyartech.scram_sasl.common.StringPrep;
import com.bolyartech.scram_sasl.server.ScramSaslServerProcessor;
import com.bolyartech.scram_sasl.server.ScramSha1SaslServerProcessor;


/**
 * Shows how to use both client and server with SCRAM SHA-1
 */
public class ScramSha1Example {
    public static void main(String[] args) {
        ScramSha1SaslServerProcessor.Listener serverListener = new ScramSha1SaslServerProcessor.Listener() {

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


        ScramSaslServerProcessor.UserDataLoader loader = new ScramSaslServerProcessor.UserDataLoader() {

            @Override
            public void loadUserData(String username, long connectionId, ScramSaslServerProcessor interested) {
                //noinspection SpellCheckingInspection
                interested.onUserDataLoaded(
                        new ScramSaslServerProcessor.UserData("TWLQ7cNG4uHZn38AlBSE7XacApO76SjN",
                        4096,
                        "bEBbN+QCeFi1rtCQPn/15+mvuNg=",
                        "pxF02K1QQ/t5PcweqxjzZwPOolU="
                ));
            }
        };

        MyToServerSender toServerSender = new MyToServerSender();
        ScramSha1SaslClientProcessor client = new ScramSha1SaslClientProcessor(clientListener, toServerSender);

        MyToClientSender toClientSender = new MyToClientSender(client);
        ScramSha1SaslServerProcessor server = new ScramSha1SaslServerProcessor(1, serverListener, loader,
                toClientSender);

        toServerSender.setServer(server);

        try {
            client.start("ogre", "ogre1234");
        } catch (StringPrep.StringPrepError stringPrepError) {
            stringPrepError.printStackTrace();
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
            } catch (SaslScramException e) {
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
            } catch (SaslScramException e) {
                e.printStackTrace();
            }
        }


        public void setServer(ScramSaslServerProcessor server) {
            mServer = server;
        }
    }
}
