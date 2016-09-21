package com.bolyartech.scram_sasl.client;



import com.bolyartech.scram_sasl.common.Base64;
import com.bolyartech.scram_sasl.common.SaslScramException;
import com.bolyartech.scram_sasl.common.ScramUtils;
import com.bolyartech.scram_sasl.common.StringPrep;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;


abstract public class AbstractScramSaslClientProcessor implements ScramSaslClientProcessor {
    private static final byte[] INT_1 = new byte[]{0, 0, 0, 1};
    private static final String GS2_HEADER = "n,,";
    private static final Charset ASCII = Charset.forName("ASCII");


    private final ScramSaslClientProcessor.Listener mListener;
    private final Sender mSender;
    private final String mDigestName;
    private final String mHmacName;
    private final String mClientNonce = UUID.randomUUID().toString();
    private String mUsername;
    private String mPassword;
    private State mState = State.INITIAL;

    private volatile boolean mIsSuccess = false;
    private volatile boolean mAborted = false;

    private String mClientFirstMessageBare;
    private String mServerNonce;
    private String mSalt;
    private int mIterations;
    private byte[] mServerSignature;


    public AbstractScramSaslClientProcessor(Listener listener, Sender sender, String digestName, String hmacName) {

        mListener = listener;
        mSender = sender;
        mDigestName = digestName;
        mHmacName = hmacName;
    }


    @Override
    public synchronized void onMessage(String message) throws SaslScramException {
        if (mState != State.ENDED) {
            switch (mState) {
                case INITIAL:
                    notifyFail();
                case CLIENT_FIRST_SENT:
                    String msg = handleServerFirst(message);
                    if (msg != null) {
                        mState = State.CLIENT_FINAL_SENT;
                        mSender.sendMessage(msg);
                    } else {
                        mState = State.ENDED;
                        notifyFail();
                    }
                    break;
                case CLIENT_FINAL_SENT:
                    if (handleServerFinal(message)) {
                        mIsSuccess = true;
                        notifySuccess();
                    } else {
                        notifyFail();
                    }
                    mState = State.ENDED;
                    break;
            }
        }
    }


    private boolean handleServerFinal(String message) {
        String[] parts = message.split(",");
        if (!parts[0].startsWith("v=")) {
            return false;
        }
        byte[] serverSignature = Base64.decode(parts[0].substring(2));

        return Arrays.equals(serverSignature, serverSignature);
    }


    private String handleServerFirst(String message) throws SaslScramException {
        String[] parts = message.split(",");
        if (parts.length < 3) {
            return null;
        } else if (parts[0].startsWith("m=")) {
            return null;
        } else if (!parts[0].startsWith("r=")) {
            return null;
        }

        String nonce = parts[0].substring(2);

        if (!nonce.startsWith(mClientNonce)) {
            return null;
        }

        mServerNonce = nonce;
        if (!parts[1].startsWith("s=")) {
            return null;
        }
        mSalt = parts[1].substring(2);
        if (!parts[2].startsWith("i=")) {
            return null;
        }
        String iterCountString = parts[2].substring(2);
        mIterations = Integer.parseInt(iterCountString);
        if (mIterations <= 0) {
            return null;
        }


        try {
            byte[] saltedPassword = ScramUtils.generateSaltedPassword(mPassword,
                    Base64.decode(mSalt),
                    mIterations,
                    mHmacName);


            String clientFinalMessageWithoutProof = "c=" + Base64.encodeBytes(GS2_HEADER.getBytes(ASCII))
                    + ",r=" + mServerNonce;

            String authMessage = mClientFirstMessageBare + "," + message + "," + clientFinalMessageWithoutProof;

            byte[] clientKey = ScramUtils.computeHmac(saltedPassword, mHmacName, "Client Key");
            byte[] storedKey = MessageDigest.getInstance(mDigestName).digest(clientKey);

            byte[] clientSignature = ScramUtils.computeHmac(storedKey, mHmacName, authMessage);

            byte[] clientProof = clientKey.clone();
            for (int i = 0; i < clientProof.length; i++) {
                clientProof[i] ^= clientSignature[i];
            }
            byte[] serverKey = ScramUtils.computeHmac(saltedPassword, mHmacName, "Server Key");
            mServerSignature = ScramUtils.computeHmac(serverKey, mHmacName, authMessage);


            return clientFinalMessageWithoutProof + ",p=" + Base64.encodeBytes(clientProof);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new SaslScramException(e);
        }
    }


    @Override
    public synchronized void abort() {
        mAborted = true;
        mState = State.ENDED;
    }


    @Override
    public synchronized boolean isEnded() {
        return mState == State.ENDED;
    }


    @Override
    public boolean isSuccess() {
        return mIsSuccess;
    }


    private void notifySuccess() {
        mListener.onSuccess();
    }


    private void notifyFail() {
        mListener.onFailure();
    }


    @Override
    public synchronized void start(String username, String password) throws StringPrep.StringPrepError {
        mUsername = username;
        mPassword = password;

        mClientFirstMessageBare = "n=" + StringPrep.prepAsQueryString(mUsername) + ",r=" + mClientNonce;
        mState = State.CLIENT_FIRST_SENT;
        mSender.sendMessage(GS2_HEADER + mClientFirstMessageBare);
    }


    @Override
    public boolean isAborted() {
        return mAborted;
    }


    enum State {
        INITIAL,
        CLIENT_FIRST_SENT,
        CLIENT_FINAL_SENT,
        ENDED
    }
}
