package lt.viko.eif.nychyporuk.passwordmanager.manager;

import lt.viko.eif.nychyporuk.passwordmanager.cryptoutil.AES;
import lt.viko.eif.nychyporuk.passwordmanager.cryptoutil.DES;
import lt.viko.eif.nychyporuk.passwordmanager.cryptoutil.RSA;
import lt.viko.eif.nychyporuk.passwordmanager.cryptoutil.Util;
import lt.viko.eif.nychyporuk.passwordmanager.model.PasswordRecord;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class PasswordManager {

    private File file;
    private File keysFile;

    private byte[] AES_KEY;
    private byte[] DES_KEY;
    private KeyPair RSA_KEY_PAIR;

    public PasswordManager(String username, File file) {
        this.file = file;
        generateKeys(username);
    }

    private void generateKeys(String username) {
        this.keysFile = new File("src/main/resources/" + username + ".txt");
        if (!this.keysFile.exists()) {
            try {
                this.keysFile.createNewFile();
                KeyManager.generateKeys(keysFile);
            } catch (IOException e) {
                System.out.println("Couldn't create keys file." + e.getMessage());
                return;
            }
        }

        AES_KEY = KeyManager.getAESKey(keysFile);
        DES_KEY = KeyManager.getDESKey(keysFile);
        RSA_KEY_PAIR = KeyManager.getRSAKeyPair(keysFile);
    }

    public void printPasswords() {
        boolean isEmpty = true;
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
                isEmpty = false;
            }
        } catch (IOException e) {
            System.out.println("Couldn't print passwords." + e.getMessage());
        }

        if (isEmpty) {
            System.out.println("There are no passwords.");
        }
    }

    public PasswordRecord getPasswordData() {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter title: ");
        String title = scanner.nextLine();
        System.out.print("Enter URL/application: ");
        String url = scanner.nextLine();
        System.out.print("Enter other information: ");
        String other = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        System.out.print("Enter algorithm (AES/DES/RSA): ");
        String algorithm = scanner.nextLine();

        return new PasswordRecord(title, url, other, password, algorithm);
    }

    public void addPassword(PasswordRecord record) {

        if (findPasswordByTitle(record.getTitle()) != null) {
            System.out.println("Password with such title already exists.");
            return;
        }

        String data = record.getTitle() + ',' + record.getUrl() + ',' + record.getOther() + ',';
        try {
            String password = record.getPassword();
            String algorithm = record.getAlgorithm();
            switch (record.getAlgorithm()) {
                case "AES":
                    data += AES.encrypt(password, AES_KEY);
                    break;
                case "DES":
                    data += DES.encrypt(password, DES_KEY);
                    break;
                case "RSA":
                    data += RSA.encrypt(password, RSA_KEY_PAIR.getPublic());
                    break;
                default:
                    break;
            }

            data += ',' + algorithm + "\n";
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException |
                 IllegalBlockSizeException | InvalidKeyException e) {
            System.out.println("Couldn't encrypt data." + e.getMessage());
            return;
        }

        try (OutputStream os = new FileOutputStream(file, true)) {
            os.write((data).getBytes());
            System.out.println("New password was successfully added.");
        } catch (IOException e) {
            System.out.println("Couldn't save password." + e.getMessage());
        }
    }

    private String decryptPassword(String password, String algorithm)
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException {

        return switch (algorithm) {
            case "AES" -> AES.decrypt(password, AES_KEY);
            case "DES" -> DES.decrypt(password, DES_KEY);
            case "RSA" -> RSA.decrypt(password, RSA_KEY_PAIR.getPrivate());
            default -> throw new NoSuchAlgorithmException();
        };
    }

    public String getTitle() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter title: ");
        return scanner.nextLine();
    }

    public PasswordRecord findPasswordByTitle(String searchTitle) {
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] data = line.split(",");

                if (data.length >= 5 && data[0].trim().equals(searchTitle)) {
                    String title = data[0];
                    String url = data[1];
                    String other = data[2];
                    String password = data[3];
                    String algorithm = data[4];

                    try {
                        password = decryptPassword(password, algorithm);
                        return new PasswordRecord(title, url, other, password, algorithm);
                    } catch (NoSuchPaddingException | IllegalBlockSizeException |
                             NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                        System.out.println("Couldn't decrypt password." + e.getMessage());
                    }
                }
            }
        } catch (IOException e) {
            System.out.println("Couldn't read the file." + e.getMessage());
        }

        return null;
    }

    public String getNewPassword() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter new password: ");
        return scanner.nextLine();
    }

    public void updatePasswordByTitle(String searchTitle, String newPassword) {

        PasswordRecord passwordRecord = findPasswordByTitle(searchTitle);

        if (passwordRecord != null) {
            deletePasswordByTitle(searchTitle);
            passwordRecord.setPassword(newPassword);
            addPassword(passwordRecord);
        } else {
            System.out.println("Couldn't find password by title: " + searchTitle);
        }
    }

    public void deletePasswordByTitle(String searchTitle) {
        List<String> lines = new ArrayList<>();

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] data = line.split(",");
                if (data.length >= 5 && data[0].trim().equals(searchTitle)) {
                    continue;
                }
                lines.add(line);
            }
        } catch (IOException e) {
            System.out.println("Couldn't read the file." + e.getMessage());
            return;
        }

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(file))) {
            for (String line : lines) {
                bw.write(line);
                bw.newLine();
            }
            System.out.println("Password was successfully deleted.");
        } catch (IOException e) {
            System.out.println("Couldn't write to the file." + e.getMessage());
        }
    }

    public void generateAndDisplayRandomPassword() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the desired length of the password: ");
        int length = Integer.parseInt(scanner.nextLine());
        String randomPassword = Util.generateRandomPassword(length);
        System.out.println("Generated Password: " + randomPassword);
    }
}
