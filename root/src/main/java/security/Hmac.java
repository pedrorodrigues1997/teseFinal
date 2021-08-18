package security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import oracle.security.crypto.core.SymmetricKey;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class Hmac {

    public Hmac() {
    }


    public static byte[] encodeHmac(byte[] secretKey, byte[] message) {
        byte[] hmacSha256 = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
            mac.init(secretKeySpec);
            hmacSha256 = mac.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException("Failed to calculate hmac-sha256", e);
        }
        return hmacSha256;
    }

    public String convertHmacStringToHexString(String key, String message) {
        byte[] hmacSha256 = Hmac.encodeHmac(key.getBytes(StandardCharsets.UTF_8), message.getBytes(StandardCharsets.UTF_8));
        return String.format("Hex: %032x", new BigInteger(1, hmacSha256));
    }

    public String convertHmacToHexString(byte[] hmacSha256) {
        return String.format("Hex: %032x", new BigInteger(1, hmacSha256));
    }

    public boolean compareHmac(byte[] secretKey, byte[] message, byte[] other) {
        byte[] hmacSha256 = encodeHmac(secretKey, message);
        String newStr = String.format("%032x", new BigInteger(1, hmacSha256));
        String oldStr = String.format("%032x", new BigInteger(1, other));
        if(newStr.equals(oldStr)){
            return true;
        }else{
            return false;
        }
    }
}