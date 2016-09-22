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


/**
 * Provides client side processing of the SCRAM SASL authentication
 * Skeleton implementation of ScramSaslClientProcessor
 */
@SuppressWarnings("WeakerAccess")
abstract public class AbstractScramSaslClientProcessor implements ScramSaslClientProcessor {
    private static final String GS2_HEADER = "n,,";
    private static final Charset ASCII = Charset.forName("ASCII");


    private final ScramSaslClientProcessor.Listener mListener;
    private final Sender mSender;
    private final String mDigestName;
    private final String mHmacName;
    private final String mClientNonce;
    private String mPassword;
    private State mState = State.INITIAL;

    private volatile boolean mIsSuccess = false;
    private volatile boolean mAborted = false;

    private String mClientFirstMessageBare;


    /**
     * Creates new AbstractScramSaslClientProcessor
     * @param listener Listener of the client processor (this object)
     * @param sender Sender used to send messages to the server
     * @param digestName Digest to be used
     * @param hmacName HMAC to be used
     */
    @SuppressWarnings("SameParameterValue")
    public AbstractScramSaslClientProcessor(Listener listener, Sender sender, String digestName, String hmacName) {
        this(listener, sender, digestName, hmacName, UUID.randomUUID().toString());
    }


    /**
     * Creates new AbstractScramSaslClientProcessor
     * Intended to be used in unit test (with a predefined clientNonce in order to have repeatability)
     * @param listener Listener of the client processor (this object)
     * @param sender Sender used to send messages to the server
     * @param digestName Digest to be used
     * @param hmacName HMAC to be used
     * @param clientNonce Client nonce
     */
    AbstractScramSaslClientProcessor(Listener listener,
                                            Sender sender,
                                            String digestName,
                                            String hmacName,
                                            String clientNonce) {

        if (listener == null) {
            throw new NullPointerException("Parameter listener cannot be null");
        }
        if (sender == null) {
            throw new NullPointerException("Parameter sender cannot be null");
        }
        if (ScramUtils.isNullOrEmpty(digestName)) {
            throw new NullPointerException("digestName cannot be null or empty");
        }
        if (ScramUtils.isNullOrEmpty(hmacName)) {
            throw new NullPointerException("hmacName cannot be null or empty");
        }
        if (ScramUtils.isNullOrEmpty(clientNonce)) {
            throw new NullPointerException("clientNonce cannot be null or empty");
        }

        mListener = listener;
        mSender = sender;
        mDigestName = digestName;
        mHmacName = hmacName;
        mClientNonce = clientNonce;
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


    @Override
    public synchronized void start(String username, String password) throws StringPrep.StringPrepError {
        mPassword = password;

        mClientFirstMessageBare = "n=" + StringPrep.prepAsQueryString(username) + ",r=" + mClientNonce;
        mState = State.CLIENT_FIRST_SENT;
        mSender.sendMessage(GS2_HEADER + mClientFirstMessageBare);
    }


    @Override
    public boolean isAborted() {
        return mAborted;
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

        if (!parts[1].startsWith("s=")) {
            return null;
        }
        String salt = parts[1].substring(2);
        if (!parts[2].startsWith("i=")) {
            return null;
        }
        String iterationCountString = parts[2].substring(2);
        int iterations = Integer.parseInt(iterationCountString);
        if (iterations <= 0) {
            return null;
        }


        try {
            byte[] saltedPassword = ScramUtils.generateSaltedPassword(mPassword,
                    Base64.decode(salt),
                    iterations,
                    mHmacName);


            String clientFinalMessageWithoutProof = "c=" + Base64.encodeBytes(GS2_HEADER.getBytes(ASCII))
                    + ",r=" + nonce;

            String authMessage = mClientFirstMessageBare + "," + message + "," + clientFinalMessageWithoutProof;

            byte[] clientKey = ScramUtils.computeHmac(saltedPassword, mHmacName, "Client Key");
            byte[] storedKey = MessageDigest.getInstance(mDigestName).digest(clientKey);

            byte[] clientSignature = ScramUtils.computeHmac(storedKey, mHmacName, authMessage);

            byte[] clientProof = clientKey.clone();
            for (int i = 0; i < clientProof.length; i++) {
                clientProof[i] ^= clientSignature[i];
            }

            return clientFinalMessageWithoutProof + ",p=" + Base64.encodeBytes(clientProof);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new SaslScramException(e);
        }
    }


    private void notifySuccess() {
        mListener.onSuccess();
    }


    private void notifyFail() {
        mListener.onFailure();
    }


    enum State {
        INITIAL,
        CLIENT_FIRST_SENT,
        CLIENT_FINAL_SENT,
        ENDED
    }
}
