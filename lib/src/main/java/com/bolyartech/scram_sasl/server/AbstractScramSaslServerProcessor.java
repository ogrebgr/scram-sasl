package com.bolyartech.scram_sasl.server;

import com.bolyartech.scram_sasl.common.Base64;
import com.bolyartech.scram_sasl.common.SaslScramException;
import com.bolyartech.scram_sasl.common.ScramUtils;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Provides server side processing of the SCRAM SASL authentication
 * Skeleton implementation of ScramSaslServerProcessor
 */
@SuppressWarnings({"WeakerAccess", "unused"})
abstract class AbstractScramSaslServerProcessor implements ScramSaslServerProcessor {
    private static final Pattern
            CLIENT_FIRST_MESSAGE = Pattern.compile("^(([pny])=?([^,]*),([^,]*),)(m?=?[^,]*,?n=([^,]*),r=([^,]*),?.*)$"),
            CLIENT_FINAL_MESSAGE = Pattern.compile("(c=([^,]*),r=([^,]*)),p=(.*)$");

    private final long mConnectionId;
    private final String mDigestName;
    private final String mHmacName;
    private final Listener mListener;
    private final UserDataLoader mUserDataLoader;
    private final Sender mSender;
    private final String mServerPartNonce;

    private State mState = State.INITIAL;

    private volatile boolean mIsSuccess = false;
    private volatile boolean mAborted = false;

    private String mUsername;
    private String mServerFirstMessage;
    private String mClientFirstMessageBare;
    private String mNonce;
    private UserData mUserData;


    /**
     * Creates new AbstractScramSaslServerProcessor
     * @param connectionId ID of the client connection
     * @param listener Listener
     * @param userDataLoader loader for user data
     * @param sender Sender used to send messages to the clients
     * @param digestName Digest to be used
     * @param hmacName HMAC to be used
     */
    public AbstractScramSaslServerProcessor(final long connectionId,
                                            final Listener listener,
                                            final UserDataLoader userDataLoader,
                                            final Sender sender,
                                            final String digestName,
                                            final String hmacName) {

        this(connectionId, listener, userDataLoader, sender, digestName, hmacName, UUID.randomUUID().toString());
    }


    /**
     * Creates new AbstractScramSaslServerProcessor.
     * Intended to be used in unit test (with a predefined serverPartNonce in order to have repeatability)
     * @param connectionId ID of the client connection
     * @param listener Listener
     * @param userDataLoader loader for user data
     * @param sender Sender used to send messages to the clients
     * @param digestName Digest to be used
     * @param hmacName HMAC to be used
     * @param serverPartNonce In its first message server sends a nonce which contains the client nonce and server part nonce
     */
    AbstractScramSaslServerProcessor(final long connectionId,
                                     final Listener listener,
                                     final UserDataLoader userDataLoader,
                                     final Sender sender,
                                     final String digestName,
                                     final String hmacName,
                                     final String serverPartNonce) {

        if (listener == null) {
            throw new NullPointerException("listener cannot be null");
        }
        if (userDataLoader == null) {
            throw new NullPointerException("userDataLoader cannot be null");
        }
        if (sender == null) {
            throw new NullPointerException("sender cannot be null");
        }
        if (ScramUtils.isNullOrEmpty(digestName)) {
            throw new NullPointerException("digestName cannot be null or empty");
        }
        if (ScramUtils.isNullOrEmpty(hmacName)) {
            throw new NullPointerException("hmacName cannot be null or empty");
        }
        if (ScramUtils.isNullOrEmpty(serverPartNonce)) {
            throw new NullPointerException("serverPartNonce cannot be null or empty");
        }

        mConnectionId = connectionId;
        mDigestName = digestName;
        mHmacName = hmacName;
        mListener = listener;
        mUserDataLoader = userDataLoader;
        mSender = sender;
        mServerPartNonce = serverPartNonce;
    }


    public synchronized void onMessage(String message) throws SaslScramException {
        if (mState != State.ENDED) {
            switch (mState) {
                case INITIAL:
                    if (handleClientFirst(message)) {
                        mState = State.WAITING_FOR_USER_DATA;
                    } else {
                        mState = State.ENDED;
                        notifyFail();
                    }
                    break;
                case WAITING_FOR_USER_DATA:
                    mState = State.ENDED;
                    notifyFail();
                    break;
                case SERVER_FIRST_SENT:
                    mState = State.ENDED;
                    String msg = handleClientFinal(message);
                    if (msg != null) {
                        mSender.sendMessage(mConnectionId, msg);
                        mIsSuccess = true;
                        mListener.onSuccess(mConnectionId);
                    } else {
                        mListener.onFailure(mConnectionId);
                    }
                    break;
            }
        }
    }


    @Override
    public synchronized void onUserDataLoaded(UserData data) {
        mUserData = data;
        mServerFirstMessage = String.format("r=%s,s=%s,i=%d",
                mNonce,
                data.salt,
                data.iterations);

        mState = State.SERVER_FIRST_SENT;
        mSender.sendMessage(mConnectionId, mServerFirstMessage);
    }


    @Override
    public synchronized void abort() {
        mAborted = true;
        mState = State.ENDED;
    }


    @Override
    public long getConnectionId() {
        return mConnectionId;
    }


    @Override
    public synchronized String getAuthorizationID() {
        if (mState == State.ENDED && mIsSuccess) {
            return mUsername;
        } else {
            throw new IllegalStateException("Don't call this method before the successful end");
        }
    }


    @Override
    public synchronized boolean isEnded() {
        return mState == State.ENDED;
    }


    @Override
    public boolean isAborted() {
        return mAborted;
    }


    @Override
    public boolean isSuccess() {
        if (mState == State.ENDED && mIsSuccess) {
            return mIsSuccess;
        } else {
            throw new IllegalStateException("Don't call this method before the end");
        }
    }


    private String handleClientFinal(String message) throws SaslScramException {
        Matcher m = CLIENT_FINAL_MESSAGE.matcher(message);
        if (!m.matches()) {
            return null;
        }

        String clientFinalMessageWithoutProof = m.group(1);
        String clientNonce = m.group(3);
        String proof = m.group(4);

        if (!mNonce.equals(clientNonce)) {
            return null;
        }


        String authMessage = mClientFirstMessageBare + "," + mServerFirstMessage + "," + clientFinalMessageWithoutProof;

        byte[] storedKeyArr = Base64.decode(mUserData.storedKey);

        try {
            byte[] clientSignature = ScramUtils.computeHmac(storedKeyArr, mHmacName, authMessage);
            byte[] serverSignature = ScramUtils.computeHmac(Base64.decode(mUserData.serverKey), mHmacName, authMessage);
            byte[] clientKey = clientSignature.clone();
            byte[] decodedProof = Base64.decode(proof);
            for (int i = 0; i < clientKey.length; i++) {
                clientKey[i] ^= decodedProof[i];
            }

            byte[] resultKey = MessageDigest.getInstance(mDigestName).digest(clientKey);
            if (!Arrays.equals(storedKeyArr, resultKey)) {
                return null;
            }


            return "v=" + Base64.encodeBytes(serverSignature);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new SaslScramException(e);
        }

    }


    private boolean handleClientFirst(String message) {
        Matcher m = CLIENT_FIRST_MESSAGE.matcher(message);
        if (!m.matches()) {
            return false;
        }

        mClientFirstMessageBare = m.group(5);
        mUsername = m.group(6);
        String clientNonce = m.group(7);
        mNonce = clientNonce + mServerPartNonce;

        mUserDataLoader.loadUserData(mUsername, mConnectionId, this);

        return true;
    }


    private void notifySuccess() {
        mListener.onSuccess(mConnectionId);
    }


    private void notifyFail() {
        mListener.onFailure(mConnectionId);
    }


    private enum State {
        INITIAL,
        WAITING_FOR_USER_DATA,
        SERVER_FIRST_SENT,
        ENDED
    }
}
