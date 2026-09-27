package in.bharatfinserve.pay;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;

/** Key management for UPI settlement files. */
public class KeyService {

    private static final int KEY_BITS = 2048;
    private static final String SETTLEMENT_CIPHER = "RSA/ECB/PKCS1Padding";

    public KeyPair newSettlementKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(KEY_BITS);
        return kpg.generateKeyPair();
    }

    public byte[] encryptSettlementKey(KeyPair pair, byte[] sessionKey) throws Exception {
        Cipher rsa = Cipher.getInstance(SETTLEMENT_CIPHER);
        rsa.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        return rsa.doFinal(sessionKey);
    }

    public byte[] signBatch(PrivateKey key, byte[] batch) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(key);
        sig.update(batch);
        return sig.sign();
    }

    public String idempotencyKey(byte[] request) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new java.math.BigInteger(1, md.digest(request)).toString(16);
    }

    public byte[] encryptCardToken(byte[] token) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey k = kg.generateKey();
        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aes.init(Cipher.ENCRYPT_MODE, k);
        return aes.doFinal(token);
    }

    public byte[] webhookMac(SecretKey key, byte[] body) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(body);
    }

    public SSLContext bankLinkContext() throws Exception {
        return SSLContext.getInstance("TLSv1.1");
    }
}
