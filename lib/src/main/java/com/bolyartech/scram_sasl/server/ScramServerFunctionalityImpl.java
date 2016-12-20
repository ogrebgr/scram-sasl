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


import com.bolyartech.scram_sasl.common.Base64;
import com.bolyartech.scram_sasl.common.ScramException;
import com.bolyartech.scram_sasl.common.ScramUtils;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Provides building blocks for creating SCRAM authentication server
 */
@SuppressWarnings("unused")
public class ScramServerFunctionalityImpl implements ScramServerFunctionality {
    private static final Pattern
            CLIENT_FIRST_MESSAGE = Pattern.compile("^(([pny])=?([^,]*),([^,]*),)(m?=?[^,]*,?n=([^,]*),r=([^,]*),?.*)$");
    private static final Pattern
            CLIENT_FINAL_MESSAGE = Pattern.compile("(c=([^,]*),r=([^,]*)),p=(.*)$");


    private final String mDigestName;
    private final String mHmacName;
    private final String mServerPartNonce;

    private boolean mIsSuccessful = false;
    private State mState = State.INITIAL;
    private String mClientFirstMessageBare;
    private String mNonce;
    private String mServerFirstMessage;
    private UserData mUserData;


    /**
     * Creates new ScramServerFunctionalityImpl
     * @param digestName Digest to be used
     * @param hmacName HMAC to be used
     */
    public ScramServerFunctionalityImpl(String digestName, String hmacName) {
        this(digestName, hmacName, UUID.randomUUID().toString());
    }


    /**
     /**
     * Creates new ScramServerFunctionalityImpl
     * @param digestName Digest to be used
     * @param hmacName HMAC to be used
     * @param serverPartNonce Server's part of the nonce
     */
    public ScramServerFunctionalityImpl(String digestName, String hmacName, String serverPartNonce) {
        if (ScramUtils.isNullOrEmpty(digestName)) {
            throw new NullPointerException("digestName cannot be null or empty");
        }
        if (ScramUtils.isNullOrEmpty(hmacName)) {
            throw new NullPointerException("hmacName cannot be null or empty");
        }
        if (ScramUtils.isNullOrEmpty(serverPartNonce)) {
            throw new NullPointerException("serverPartNonce cannot be null or empty");
        }

        mDigestName = digestName;
        mHmacName = hmacName;
        mServerPartNonce = serverPartNonce;
    }


    /**
     * Handles client's first message
     * @param message Client's first message
     * @return username extracted from the client message
     */
    @Override
    public String handleClientFirstMessage(String message) {
        Matcher m = CLIENT_FIRST_MESSAGE.matcher(message);
        if (!m.matches()) {
            return null;
        }

        mClientFirstMessageBare = m.group(5);
        String username = m.group(6);
        String clientNonce = m.group(7);
        mNonce = clientNonce + mServerPartNonce;

        mState = State.FIRST_CLIENT_MESSAGE_HANDLED;

        return username;
    }


    @Override
    public String prepareFirstMessage(UserData userData) {
        mUserData = userData;
        mState = State.PREPARED_FIRST;
        mServerFirstMessage = String.format("r=%s,s=%s,i=%d",
                mNonce,
                userData.salt,
                userData.iterations);

        return mServerFirstMessage;
    }


    @Override
    public String prepareFinalMessage(String clientFinalMessage) throws ScramException {
        Matcher m = CLIENT_FINAL_MESSAGE.matcher(clientFinalMessage);
        if (!m.matches()) {
            mState = State.ENDED;
            return null;
        }

        String clientFinalMessageWithoutProof = m.group(1);
        String clientNonce = m.group(3);
        String proof = m.group(4);

        if (!mNonce.equals(clientNonce)) {
            mState = State.ENDED;
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


            mIsSuccessful = true;
            mState = State.ENDED;
            return "v=" + Base64.encodeBytes(serverSignature, Base64.DONT_BREAK_LINES);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            mState = State.ENDED;
            throw new ScramException(e);
        }
    }


    @Override
    public boolean isSuccessful() {
        if (mState == State.ENDED) {
            return mIsSuccessful;
        } else {
            throw new IllegalStateException("You cannot call this method before authentication is ended. " +
                    "Use isEnded() to check that");
        }
    }


    @Override
    public boolean isEnded() {
        return mState == State.ENDED;
    }


    @Override
    public State getState() {
        return mState;
    }
}
