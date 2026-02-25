package backend;

/**
 *
 * @author marcusuy
 */
import java.io.*;
import java.net.*;
import java.security.*;
import java.time.Instant;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class ATM {
    private static final int serverport = 12345;
    private static final int TIME_WINDOW = 30; // 30 seconds window for replay protection
    private static SecretKey MasterSecret;

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        while (true) {  //Allow multiple users to log in without restarting ATM
            System.out.print("Enter client ID: ");
            String clientID = scanner.nextLine();

            // Generate RSA keypair for client
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair ATMkeyPair = keyGen.generateKeyPair();

            // Connect to server
            Socket socket = new Socket("localhost", serverport);
            ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

//------------------------ Mutual Authentication start------------------------------------------------

            // Send public key & client ID
            output.writeObject(ATMkeyPair.getPublic());
            output.writeObject(clientID);

            PublicKey BankServerPub = (PublicKey) input.readObject();
            String encryptedResponse = (String) input.readObject();
            String decryptedMessage = decryptRSA(ATMkeyPair.getPrivate(), encryptedResponse);
            String[] parts = decryptedMessage.split("[.]");
            String NK1 = parts[0];
            String serverID = parts[1];

            System.out.println("... validating connection with server " + serverID);

            // Send response nonce
            String NA = String.valueOf(new SecureRandom().nextInt(10000));
            String encryptedMessage = encryptRSA(BankServerPub, NA + "." + NK1);
            output.writeObject(encryptedMessage);

            // Receive confirmation nonce
            String encConfirmation = (String) input.readObject();
            String confirmation = decryptRSA(ATMkeyPair.getPrivate(), encConfirmation);
            if (!confirmation.equals(NA)) {
                System.out.println("Nonce verification failed for bank server");
                socket.close();
                continue;  //restart the login process
            } else {
                System.out.println(clientID + " connected successfully!");
            }
//------------------------ Mutual Authentication end------------------------------------------------

//------------------------ recieve MS key ------------------------------------------------
            String encryptedMasterSecret = (String) input.readObject();
            byte[] decodedKey = Base64.getDecoder().decode(decryptRSA(ATMkeyPair.getPrivate(), encryptedMasterSecret));
            MasterSecret = new SecretKeySpec(decodedKey, "AES");

            // Receive and print welcome message
            String welcomeMessage = (String) input.readObject();
            System.out.println("Server - " + welcomeMessage);
            int counter = 0;
            // handle password prompt and errors
            while (true) {
                String passwordprompt = (String) input.readObject();
                System.out.print("Server - " + passwordprompt);
                String password = scanner.nextLine();
                output.writeObject(password);

                String response = (String) input.readObject();
                System.out.println("Server: " + response);

                if (response.equals("Login successful!") || response.contains("Account created successfully")) {
                    break;  // Exit password loop and enter the main transaction loop
                } else if (counter == 3) {
                    socket.close();
                    return;
                }
                else {
                    System.out.println("Incorrect password. Please try again. (note: connection will be terminated after 3 attempts)");
                    counter+=1;
                    System.out.println("Attempt " + counter + "/3 failed");
                }
            }

//------------------------ atm operations loop start------------------------------------------------

            while (true) {
                System.out.print("Please enter 1 to view balance, 2 to deposit, 3 to withdraw or 'exit' to logout: ");
                String message = scanner.nextLine();

                if (message.equals("1") || message.equals("2") || message.equals("3")) {
                    long timestamp = Instant.now().getEpochSecond();
                    String signedMessage = signMessage(clientID + "::" + message + "::" + timestamp, ATMkeyPair.getPrivate());

                    String finalMessage = clientID + "::" + message + "::" + timestamp + "::" + signedMessage;
                    String mac = generateMAC(finalMessage, MasterSecret);

                    output.writeObject(Base64.getEncoder().encodeToString(encryptMessage(MasterSecret, finalMessage)));
                    output.writeObject(mac);

                    // Receive server response
                    String serverResponse = (String) input.readObject();
                    System.out.println("Server: " + serverResponse);

                    if (message.equals("2") || message.equals("3")) {
                        System.out.print("Enter amount: ");
                        String amount = scanner.nextLine();
                        output.writeObject(amount);

                        // Read transaction result
                        System.out.println("Server: " + input.readObject());
                    }
                } else if (message.equals("exit")) {
                    System.out.println("Logging out...");
                    output.writeObject("exit");  //notify server
                    socket.close();  //close socket properly before restarting login
                    break;  // return to login screen
                } else {
                    System.out.println("Invalid option.");
                }
            }
            
//------------------------ atm operations loop ends ------------------------------------------------            
        }
    }

    private static String encryptRSA(PublicKey key, String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    private static String decryptRSA(PrivateKey key, String cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }

    private static byte[] encryptMessage(SecretKey key, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message.getBytes());
    }

    private static String signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private static String generateMAC(String message, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return Base64.getEncoder().encodeToString(mac.doFinal(message.getBytes()));
    }
}
