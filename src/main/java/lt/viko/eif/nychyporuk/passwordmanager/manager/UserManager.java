package lt.viko.eif.nychyporuk.passwordmanager.manager;

import lt.viko.eif.nychyporuk.passwordmanager.cryptoutil.AES;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;

public class UserManager {

    private static final String USERS_FILE = "src/main/resources/users.csv";
    private static final String USER_FILE_PREFIX = "src/main/resources/";
    private static final SecureRandom secureRandom = new SecureRandom();

    public static byte[] generateUserKey(String password, byte[] salt) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();
        generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()), salt, 10000);
        KeyParameter key = (KeyParameter) generator.generateDerivedParameters(256);
        return key.getKey();
    }

    public static void registerUser(String username, String password) throws Exception {
        File usersFile = new File(USERS_FILE);
        if (usersFile.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(usersFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith(username + ",")) {
                        throw new Exception("User already exists.");
                    }
                }
            }
        }

        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        byte[] key = generateUserKey(password, salt);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(usersFile, true))) {
            writer.write(username + "," + Base64.toBase64String(salt) + "," + Base64.toBase64String(key) + "\n");
        }

        File userFile = new File(USER_FILE_PREFIX + username + ".csv");
        if (!userFile.exists()) {
            userFile.createNewFile();
        }

        AES.encryptFile(userFile, key);
    }

    public static byte[] loginUser(String username, String password) throws Exception {
        File usersFile = new File(USERS_FILE);
        if (!usersFile.exists()) {
            throw new Exception("No users registered.");
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(usersFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts[0].equals(username)) {
                    byte[] salt = Base64.decode(parts[1]);
                    byte[] key = generateUserKey(password, salt);
                    if (Arrays.equals(key, Base64.decode(parts[2]))) {
                        return key;
                    } else {
                        throw new Exception("Incorrect password.");
                    }
                }
            }
        }
        throw new Exception("User not found.");
    }
}
