package lt.viko.eif.nychyporuk.passwordmanager.manager;

import lt.viko.eif.nychyporuk.passwordmanager.cryptoutil.AES;
import lt.viko.eif.nychyporuk.passwordmanager.cryptoutil.DES;
import lt.viko.eif.nychyporuk.passwordmanager.cryptoutil.RSA;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyManager {

    private static final byte[] AES_KEY = "12345678901234561234567890123456".getBytes(StandardCharsets.UTF_8);

    public static void generateKeys(File file) {

        byte[] aesKey = null;
        try {
            aesKey = AES.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not generate AES key." + e.getMessage());
            return;
        }

        byte[] desKey = null;
        try {
            desKey = DES.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not generate DES key." + e.getMessage());
            return;
        }

        KeyPair rsaKeyPair = null;
        try {
            rsaKeyPair = RSA.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Couldn't generate RSA KeyPair." + e.getMessage());
            return;
        }

        String aesKeyBase64 = Base64.getEncoder().encodeToString(aesKey);
        String desKeyBase64 = Base64.getEncoder().encodeToString(desKey);
        String publicKeyBase64 = Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded());
        String privateKeyBase64 = Base64.getEncoder().encodeToString(rsaKeyPair.getPrivate().getEncoded());

        String content = String.join("\n", aesKeyBase64, desKeyBase64, publicKeyBase64, privateKeyBase64);

        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content.getBytes());
            AES.encryptFile(file, AES_KEY);
        } catch (Exception e) {
            System.out.println("Couldn't save and encrypt keys." + e.getMessage());
        }
    }

    public static byte[] getAESKey(File file) {
        try {
            AES.decryptFile(file, AES_KEY);
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] content = fis.readAllBytes();

                String[] keyParts = new String(content, StandardCharsets.UTF_8).split("\n");

                AES.encryptFile(file, AES_KEY);
                return Base64.getDecoder().decode(keyParts[0]);
            } catch (IOException e) {
                System.out.println("Failed to read file: " + e.getMessage());
                AES.encryptFile(file, AES_KEY);
                return null;
            }
        } catch (Exception e) {
            System.out.println("Couldn't decrypt keys." + e.getMessage());
            return null;
        }
    }

    public static byte[] getDESKey(File file) {
        try {
            AES.decryptFile(file, AES_KEY);
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] content = fis.readAllBytes();

                String[] keyParts = new String(content, StandardCharsets.UTF_8).split("\n");

                AES.encryptFile(file, AES_KEY);
                return Base64.getDecoder().decode(keyParts[1]);
            } catch (IOException e) {
                System.out.println("Failed to read file: " + e.getMessage());
                AES.encryptFile(file, AES_KEY);
                return null;
            }
        } catch (Exception e) {
            System.out.println("Couldn't decrypt keys." + e.getMessage());
            return null;
        }
    }

    public static KeyPair getRSAKeyPair(File file) {
        try {
            AES.decryptFile(file, AES_KEY);
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] content = fis.readAllBytes();

                String[] keyParts = new String(content, StandardCharsets.UTF_8).split("\n");
                byte[] publicKey = Base64.getDecoder().decode(keyParts[2]);
                byte[] privateKey = Base64.getDecoder().decode(keyParts[3]);

                PublicKey rsaPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));
                PrivateKey rsaPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKey));

                AES.encryptFile(file, AES_KEY);
                return new KeyPair(rsaPublicKey, rsaPrivateKey);
            } catch (IOException e) {
                System.out.println("Failed to read file: " + e.getMessage());
                AES.encryptFile(file, AES_KEY);
                return null;
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                System.out.println("Couldn't get RSA key from file: " + e.getMessage());
                AES.encryptFile(file, AES_KEY);
                return null;
            }
        } catch (Exception e) {
            System.out.println("Couldn't decrypt keys." + e.getMessage());
            return null;
        }
    }
}
