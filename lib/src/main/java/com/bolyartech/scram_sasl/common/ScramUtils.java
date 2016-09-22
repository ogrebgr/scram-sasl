
package com.bolyartech.scram_sasl.common;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * Provides static methods for working with SCRAM/SASL
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class ScramUtils {
    private static final byte[] INT_1 = new byte[]{0, 0, 0, 1};


    private ScramUtils() {
        throw new AssertionError("non-instantiable utility class");
    }


    /**
     * Generates salted password.
     * @param password Clear form password, i.e. what user typed
     * @param salt Salt to be used
     * @param iterationsCount Iterations for 'salting'
     * @param hmacName HMAC to be used
     * @return salted password
     * @throws InvalidKeyException if internal error occur while working with SecretKeySpec
     * @throws NoSuchAlgorithmException if hmacName is not supported by the java
     */
    public static byte[] generateSaltedPassword(final String password,
                                                byte[] salt,
                                                int iterationsCount,
                                                String hmacName) throws InvalidKeyException, NoSuchAlgorithmException {


        Mac mac = createHmac(password.getBytes(StandardCharsets.US_ASCII), hmacName);

        mac.update(salt);
        mac.update(INT_1);
        byte[] result = mac.doFinal();

        byte[] previous = null;
        for(int i = 1; i < iterationsCount; i++)
        {
            mac.update(previous != null? previous: result);
            previous = mac.doFinal();
            for(int x = 0; x < result.length; x++)
            {
                result[x] ^= previous[x];
            }
        }

        return result;
    }


    /**
     * Creates HMAC
     * @param keyBytes key
     * @param hmacName HMAC name
     * @return Mac
     * @throws InvalidKeyException if internal error occur while working with SecretKeySpec
     * @throws NoSuchAlgorithmException if hmacName is not supported by the java
     */
    public static Mac createHmac(final byte[] keyBytes, String hmacName) throws NoSuchAlgorithmException,
            InvalidKeyException {

        SecretKeySpec key = new SecretKeySpec(keyBytes, hmacName);
        Mac mac = Mac.getInstance(hmacName);
        mac.init(key);
        return mac;
    }


    /**
     * Computes HMAC byte array for given string
     * @param key key
     * @param hmacName HMAC name
     * @param string string for which HMAC will be computed
     * @return computed HMAC
     * @throws InvalidKeyException if internal error occur while working with SecretKeySpec
     * @throws NoSuchAlgorithmException if hmacName is not supported by the java
     */
    public static byte[] computeHmac(final byte[] key, String hmacName, final String string)
            throws InvalidKeyException, NoSuchAlgorithmException {

        Mac mac = createHmac(key, hmacName);
        mac.update(string.getBytes(StandardCharsets.US_ASCII));
        return mac.doFinal();
    }


    /**
     * Checks if string is null or empty
     * @param string String to be tested
     * @return true if the string is null or empty, false otherwise
     */
    public static boolean isNullOrEmpty(String string) {
        return string == null || string.length() == 0; // string.isEmpty() in Java 6
    }


    /**
     * Computes the data associated with new password like salted password, keys, etc
     *
     * This method is supposed to be used by a server when user provides new clear form password.
     * We don't want to save it that way so we generate salted password and store it along with
     * other data required by the SCRAM mechanism
     * @param passwordClearText Clear form password, i.e. as provided by the user
     * @param salt Salt to be used
     * @param iterations  Iterations for 'salting'
     * @param hmacName HMAC name to be used
     * @param digestName Digest name to be used
     * @return new password data
     * @throws NoSuchAlgorithmException if hmacName is not supported by the java
     * @throws InvalidKeyException InvalidKeyException if internal error occur while working with SecretKeySpec
     */
    public static NewPasswordByteArrayData newPassword(String passwordClearText,
                                              byte[] salt,
                                              int iterations,
                                              String hmacName,
                                              String digestName)
            throws NoSuchAlgorithmException, InvalidKeyException {


        byte[] saltedPassword = ScramUtils.generateSaltedPassword(passwordClearText,
                salt,
                iterations,
                hmacName);

        byte[] clientKey = ScramUtils.computeHmac(saltedPassword, hmacName, "Client Key");
        byte[] storedKey = MessageDigest.getInstance(digestName).digest(clientKey);
        byte[] serverKey = ScramUtils.computeHmac(saltedPassword, hmacName, "Server Key");

        return new NewPasswordByteArrayData(saltedPassword, salt, clientKey, storedKey, serverKey, iterations);
    }


    /**
     * Transforms NewPasswordByteArrayData into NewPasswordStringData into database friendly (string) representation
     * Uses Base64 to encode the byte arrays into strings
     * @param ba Byte array data
     * @return String data
     */
    public static NewPasswordStringData byteArrayToStringData(NewPasswordByteArrayData ba) {
        return new NewPasswordStringData(Base64.encodeBytes(ba.saltedPassword),
                Base64.encodeBytes(ba.salt),
                Base64.encodeBytes(ba.clientKey),
                Base64.encodeBytes(ba.storedKey),
                Base64.encodeBytes(ba.serverKey),
                ba.iterations
                );
    }


    /**
     * New password data in database friendly format, i.e. Base64 encoded strings
     */
    @SuppressWarnings("unused")
    public static class NewPasswordStringData {
        /**
         * Salted password
         */
        public final String saltedPassword;
        /**
         * Used salt
         */
        public final String salt;
        /**
         * Client key
         */
        public final String clientKey;
        /**
         * Stored key
         */
        public final String storedKey;
        /**
         * Server key
         */
        public final String serverKey;
        /**
         * Iterations for slating
         */
        public final int iterations;


        /**
         * Creates new NewPasswordStringData
         * @param saltedPassword Salted password
         * @param salt Used salt
         * @param clientKey Client key
         * @param storedKey Stored key
         * @param serverKey Server key
         * @param iterations Iterations for slating
         */
        public NewPasswordStringData(String saltedPassword,
                                     String salt,
                                     String clientKey,
                                     String storedKey,
                                     String serverKey,
                                     int iterations) {
            this.saltedPassword = saltedPassword;
            this.salt = salt;
            this.clientKey = clientKey;
            this.storedKey = storedKey;
            this.serverKey = serverKey;
            this.iterations = iterations;
        }
    }


    /**
     * New password data in byte array format
     */
    @SuppressWarnings("unused")
    public static class NewPasswordByteArrayData {
        /**
         * Salted password
         */
        public final byte[] saltedPassword;
        /**
         * Used salt
         */
        public final byte[] salt;
        /**
         * Client key
         */
        public final byte[] clientKey;
        /**
         * Stored key
         */
        public final byte[] storedKey;
        /**
         * Server key
         */
        public final byte[] serverKey;
        /**
         * Iterations for slating
         */
        public final int iterations;


        /**
         * Creates new NewPasswordByteArrayData
         * @param saltedPassword Salted password
         * @param salt Used salt
         * @param clientKey Client key
         * @param storedKey Stored key
         * @param serverKey Server key
         * @param iterations Iterations for slating
         */
        public NewPasswordByteArrayData(byte[] saltedPassword,
                                        byte[] salt,
                                        byte[] clientKey,
                                        byte[] storedKey,
                                        byte[] serverKey,
                                        int iterations) {

            this.saltedPassword = saltedPassword;
            this.salt = salt;
            this.clientKey = clientKey;
            this.storedKey = storedKey;
            this.serverKey = serverKey;
            this.iterations = iterations;
        }
    }
}
