package lt.viko.eif.nychyporuk.passwordmanager.cryptoutil;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class DES {

    private static final String ALGORITHM = "DES/ECB/PKCS5Padding";
    private static final String ALGORITHM_KEY_SPEC = "DES";

    public static String encrypt(String input, byte[] key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException,
            IllegalBlockSizeException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM_KEY_SPEC);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, byte[] key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException,
            IllegalBlockSizeException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM_KEY_SPEC);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    public static byte[] generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_KEY_SPEC);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }
}

