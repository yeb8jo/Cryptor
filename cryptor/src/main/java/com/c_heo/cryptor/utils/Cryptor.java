package com.c_heo.cryptor.utils;

import android.util.Base64;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by c-heo on 2016/09/07.
 */
public class Cryptor {
    private Cryptor() { }

    public static Aes Aes(String key) {
        return new Aes(key) {
            @Override
            public String encode(String message) throws GeneralSecurityException {
                return super.encode(message);
            }

            @Override
            public String decode(String message) throws GeneralSecurityException {
                return super.decode(message);
            }
        };
    }

    public static Sha Sha(String key) {
        return new Sha(key) {
            @Override
            public String hashing(String message) throws GeneralSecurityException {
                return super.hashing(message);
            }
        };
    }

    public static abstract class Aes {
        private static final String AES_MODE = "AES/CBC/PKCS7Padding";
        private static final String CHARSET = "UTF-8";

        private String iv;
        private Key keySpec;

        public Aes(String key) {
            this.iv = key.substring(0, 16);

            byte[] keyBytes = new byte[16];
            byte[] b = new byte[0];
            b = key.getBytes(Charset.forName(CHARSET));
            int len = b.length;
            if(len > keyBytes.length)
                len = keyBytes.length;
            System.arraycopy(b, 0, keyBytes, 0, len);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            this.keySpec = keySpec;
        }

public class Cryptor {
    private Cryptor() { }

    public static Aes Aes(String key) {
        return new Aes(key) {
            @Override
            public String encode(String message) throws GeneralSecurityException {
                return super.encode(message);
            }

            @Override
            public String decode(String message) throws GeneralSecurityException {
                return super.decode(message);
            }
        };
    }

    public static Sha Sha(String key) {
        return new Sha(key) {
            @Override
            public String hashing(String message) throws GeneralSecurityException {
                return super.hashing(message);
            }
        };
    }

    public static Md5 Md5() {
        return new Md5() {
            @Override
            public String hashing(String message) {
                return super.hashing(message);
            }
        };
    }


    /**
     * 暗号化復号化
     *
     * 形式 AES256
     */
    public static abstract class Aes {
        private static final String AES_MODE = "AES/CBC/PKCS7Padding";
        private static final String CHARSET = "UTF-8";

        private String iv;
        private Key keySpec;

        public Aes(String key) {
            this.iv = key.substring(0, 16);

            byte[] keyBytes = new byte[16];
            byte[] b = key.getBytes(Charset.forName(CHARSET));
            int len = b.length;
            if(len > keyBytes.length) {
                len = keyBytes.length;
            }

            System.arraycopy(b, 0, keyBytes, 0, len);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            this.keySpec = keySpec;
        }

        // 暗号化
        public String encode(String message) throws GeneralSecurityException {
            Cipher c = Cipher.getInstance(AES_MODE);
            c.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes()));

            byte[] encrypted = c.doFinal(message.getBytes(Charset.forName(CHARSET)));
            return Base64.encodeToString(encrypted, Base64.NO_WRAP);
        }

        // 復号化
        public String decode(String message) throws GeneralSecurityException {
            Cipher c = Cipher.getInstance(AES_MODE);
            c.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes(Charset.forName(CHARSET))));

            byte[] byteStr = Base64.decode(message.getBytes(), Base64.NO_WRAP);

            return new String(c.doFinal(byteStr),Charset.forName(CHARSET));
        }

    }

    /**
     * ハッシュ化
     *
     * 形式 SHA256
     */
    public static abstract class Sha {
        private static final String HASH_MODE = "HmacSHA256";
        private static final String CHARSET = "UTF-8";
        private final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

        private String hashKey;

        public Sha(String hashKey) {
            this.hashKey = hashKey;
        }

        public String hashing(String message) throws GeneralSecurityException {
            Mac sha256_HMAC = Mac.getInstance(HASH_MODE);
            SecretKeySpec secret_key = new SecretKeySpec(hashKey.getBytes(), HASH_MODE);
            sha256_HMAC.init(secret_key);

            byte[] hash = sha256_HMAC.doFinal(message.getBytes(Charset.forName(CHARSET)));
            return bytesToHex(hash);
        }

        private String bytesToHex(final byte[] data ) {
            final int l = data.length;
            final char[] hexChars = new char[l<<1];
            for( int i=0, j =0; i < l; i++ ) {
                hexChars[j++] = HEX_DIGITS[(0xF0 & data[i]) >>> 4];
                hexChars[j++] = HEX_DIGITS[0x0F & data[i]];
            }
            return new String(hexChars);
        }
    }

    /**
     * ハッシュ化
     *
     * 形式 MD5
     */
    public static abstract class Md5 {
        private static final String HASH_MODE = "MD5";

        public Md5() { }

        public String hashing(String message){
            MessageDigest md = null;
            try {
                md = MessageDigest.getInstance(HASH_MODE);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            md.reset();
            md.update(message.getBytes());
            byte[] a = md.digest();
            int len = a.length;
            StringBuilder sb = new StringBuilder(len << 1);
            for (int i = 0; i < len; i++) {
                sb.append(Character.forDigit((a[i] & 0xf0) >> 4, 16));
                sb.append(Character.forDigit(a[i] & 0x0f, 16));
            }
            return sb.toString();
        }
    }


}
