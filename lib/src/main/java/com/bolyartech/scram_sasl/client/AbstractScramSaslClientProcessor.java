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

package com.bolyartech.scram_sasl.client;

import com.bolyartech.scram_sasl.common.ScramException;
import com.bolyartech.scram_sasl.common.ScramUtils;

import java.util.UUID;


/**
 * Provides client side processing of the SCRAM SASL authentication
 * Skeleton implementation of ScramSaslClientProcessor
 */
@SuppressWarnings("WeakerAccess")
abstract public class AbstractScramSaslClientProcessor implements ScramSaslClientProcessor {
    private final ScramSaslClientProcessor.Listener mListener;
    private final Sender mSender;
    private String mPassword;
    private State mState = State.INITIAL;

    private volatile boolean mIsSuccess = false;
    private volatile boolean mAborted = false;

    private ScramClientFunctionality mScramClientFunctionality;


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

        mScramClientFunctionality = new ScramClientFunctionalityImpl(digestName, hmacName, clientNonce);

        mListener = listener;
        mSender = sender;
    }


    @Override
    public synchronized void onMessage(String message) throws ScramException {
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
    public synchronized void start(String username, String password) throws ScramException {
        mPassword = password;

        mState = State.CLIENT_FIRST_SENT;
        mSender.sendMessage(mScramClientFunctionality.prepareFirstMessage(username));
    }


    @Override
    public boolean isAborted() {
        return mAborted;
    }


    private boolean handleServerFinal(String message) {
        return mScramClientFunctionality.checkServerFinalMessage(message);
    }


    private String handleServerFirst(String message) throws ScramException {
        return mScramClientFunctionality.prepareFinalMessage(mPassword, message);
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
