package lt.viko.eif.nychyporuk.passwordmanager;

import lt.viko.eif.nychyporuk.passwordmanager.cryptoutil.AES;
import lt.viko.eif.nychyporuk.passwordmanager.manager.PasswordManager;
import lt.viko.eif.nychyporuk.passwordmanager.manager.UserManager;
import lt.viko.eif.nychyporuk.passwordmanager.model.PasswordRecord;

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.*;
import java.util.Scanner;

public class Main {

    private static final String USER_FILE_PREFIX = "src/main/resources/";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        menuLoop:
        while (true) {
            System.out.print("""
                    Select an option:
                    1) Register
                    2) Login
                    0) Exit
                    """);
            String choice = scanner.nextLine();

            try {
                switch (choice) {
                    case "1": {
                        System.out.print("Enter username: ");
                        String username = scanner.nextLine();
                        System.out.print("Enter password: ");
                        String password = scanner.nextLine();

                        UserManager.registerUser(username, password);

                        System.out.println("User registered successfully.");
                        break;
                    }
                    case "2": {
                        System.out.print("Enter username: ");
                        String username = scanner.nextLine();
                        System.out.print("Enter password: ");
                        String password = scanner.nextLine();

                        byte[] key = UserManager.loginUser(username, password);
                        File userFile = new File(USER_FILE_PREFIX + username + ".csv");
                        AES.decryptFile(userFile, key);
                        System.out.println("Login successful.");

                        managePasswords(username, password, userFile, key);

                        AES.encryptFile(userFile, key);
                        break;
                    }
                    case "0":
                        break menuLoop;
                    default:
                        System.out.println("Invalid option.");
                        break;
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }

    private static void managePasswords(String username, String password, File file, byte[] key) {
        Scanner scanner = new Scanner(System.in);
        PasswordManager passwordManager = new PasswordManager(username, file);

        passwordsLoop:
        while (true) {
            System.out.print("""
                    Select an option:
                    1) View passwords
                    2) Add password
                    3) Find password by title
                    4) Update password by title
                    5) Delete password by title
                    6) Generate random password
                    0) Logout
                    """);
            String choice = scanner.nextLine();

            switch (choice) {
                case "1":
                    passwordManager.printPasswords();
                    break;
                case "2":
                    passwordManager.addPassword(passwordManager.getPasswordData());
                    break;
                case "3":
                    PasswordRecord record = passwordManager.findPasswordByTitle(passwordManager.getTitle());
                    if (record != null) {
                        System.out.println("Password found. Show it? (y/n): ");
                        char showChoice = scanner.nextLine().charAt(0);
                        if (showChoice == 'y') {
                            System.out.println(record);
                            System.out.println("Copy password to clipboard? (y/n): ");
                            char copyChoice = scanner.nextLine().charAt(0);
                            if (copyChoice == 'y') {
                                copyToClipboard(record.getPassword());
                                System.out.println("Password copied to clipboard.");
                            }
                        }
                    } else {
                        System.out.println("Password not found.");
                    }
                    break;
                case "4":
                    passwordManager.updatePasswordByTitle(passwordManager.getTitle(),
                            passwordManager.getNewPassword());
                    break;
                case "5":
                    passwordManager.deletePasswordByTitle(passwordManager.getTitle());
                    break;
                case "6":
                    passwordManager.generateAndDisplayRandomPassword();
                    break;
                case "0":
                    break passwordsLoop;
                default:
                    System.out.println("Invalid option.");
                    break;
            }
        }
    }

    private static void copyToClipboard(String text) {
        StringSelection stringSelection = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
    }
}
