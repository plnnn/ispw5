package lt.viko.eif.nychyporuk.passwordmanager.cryptoutil;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AES {

    private static final String ALGORITHM = "AES/ECB/PKCS5PADDING";
    private static final String ALGORITHM_KEY_SPEC = "AES";

    public static String encrypt(String input, byte[] key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException,
            IllegalBlockSizeException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM_KEY_SPEC);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, byte[] key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException,
            IllegalBlockSizeException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM_KEY_SPEC);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    private static byte[] readFile(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return fis.readAllBytes();
        }
    }

    private static void writeFile(File file, byte[] content) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content);
        }
    }

    public static void encryptFile(File file, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM_KEY_SPEC);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] fileContent = readFile(file);
        byte[] encryptedContent = cipher.doFinal(fileContent);
        writeFile(file, encryptedContent);
    }

    public static void decryptFile(File file, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM_KEY_SPEC);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] fileContent = readFile(file);
        byte[] decryptedContent = cipher.doFinal(fileContent);
        writeFile(file, decryptedContent);
    }

    public static byte[] generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_KEY_SPEC);
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }
}
