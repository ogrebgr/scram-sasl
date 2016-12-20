/*
 * Copyright 2016 Ognyan Bankov
 * <p>
 * All rights reserved. Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.bolyartech.scram_sasl.server;


import com.bolyartech.scram_sasl.common.ScramException;
import com.bolyartech.scram_sasl.common.ScramUtils;

import java.util.UUID;


/**
 * Provides server side processing of the SCRAM SASL authentication
 * Skeleton implementation of ScramSaslServerProcessor
 */
@SuppressWarnings({"WeakerAccess", "unused"})
abstract class AbstractScramSaslServerProcessor implements ScramSaslServerProcessor {

    private final long mConnectionId;
    private final Listener mListener;
    private final UserDataLoader mUserDataLoader;
    private final Sender mSender;

    private State mState = State.INITIAL;

    private volatile boolean mIsSuccess = false;
    private volatile boolean mAborted = false;
    private String mUsername;
    private ScramServerFunctionality mScramServerFunctionality;


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
        mScramServerFunctionality = new ScramServerFunctionalityImpl(digestName, hmacName, serverPartNonce);

        mConnectionId = connectionId;
        mListener = listener;
        mUserDataLoader = userDataLoader;
        mSender = sender;
    }


    public synchronized void onMessage(String message) throws ScramException {
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
        String serverFirstMessage = mScramServerFunctionality.prepareFirstMessage(data);
        mState = State.SERVER_FIRST_SENT;
        mSender.sendMessage(mConnectionId, serverFirstMessage);
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


    private String handleClientFinal(String message) throws ScramException {
        mState = State.ENDED;
        String finalMessage = mScramServerFunctionality.prepareFinalMessage(message);
        if (finalMessage != null) {
            mIsSuccess = true;
            mState = State.ENDED;
            return finalMessage;
        } else {
            return null;
        }
    }


    private boolean handleClientFirst(String message) {
        mUsername = mScramServerFunctionality.handleClientFirstMessage(message);

        if (mUsername != null) {
            mUserDataLoader.loadUserData(mUsername, mConnectionId, this);
            return true;
        } else {
            return false;
        }
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
