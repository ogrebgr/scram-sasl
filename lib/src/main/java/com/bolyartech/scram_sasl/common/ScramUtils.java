package com.bolyartech.scram_sasl.common;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class ScramUtils {
    private static final byte[] INT_1 = new byte[]{0, 0, 0, 1};


    private ScramUtils() {
        throw new AssertionError("non-instantiable utility class");
    }


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


    public static Mac createHmac(final byte[] keyBytes, String hmacName) throws NoSuchAlgorithmException,
            InvalidKeyException {

        SecretKeySpec key = new SecretKeySpec(keyBytes, hmacName);
        Mac mac = Mac.getInstance(hmacName);
        mac.init(key);
        return mac;
    }


    public static byte[] computeHmac(final byte[] key, String hmacName, final String string)
            throws InvalidKeyException, NoSuchAlgorithmException {

        Mac mac = createHmac(key, hmacName);
        mac.update(string.getBytes(StandardCharsets.US_ASCII));
        return mac.doFinal();
    }


    public static boolean isNullOrEmpty(String string) {
        return string == null || string.length() == 0; // string.isEmpty() in Java 6
    }


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


    public static NewPasswordStringData byteArrayToStringData(NewPasswordByteArrayData ba) {
        return new NewPasswordStringData(Base64.encodeBytes(ba.saltedPassword),
                Base64.encodeBytes(ba.salt),
                Base64.encodeBytes(ba.clientKey),
                Base64.encodeBytes(ba.storedKey),
                Base64.encodeBytes(ba.serverKey),
                ba.iterations
                );
    }


    public static class NewPasswordStringData {
        public final String saltedPassword;
        public final String salt;
        public final String clientKey;
        public final String storedKey;
        public final String serverKey;
        public final int iterations;


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


    public static class NewPasswordByteArrayData {
        public final byte[] saltedPassword;
        public final byte[] salt;
        public final byte[] clientKey;
        public final byte[] storedKey;
        public final byte[] serverKey;
        public final int iterations;

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
