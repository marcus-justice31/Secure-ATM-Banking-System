package backend;

/**
 *
 * @author marcusuy
 */
import java.io.*;
import java.net.*;
import java.security.*;
import java.time.Instant;
//import java.time.Instant;
import java.util.*;
import javax.crypto.*;
//import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class BankServer {
    private static final int PORT = 12345;
    private static KeyPair bankKeyPair;
    private static SecretKey MasterSecret;
    private static final Map<String, ObjectOutputStream> clients = new HashMap<>();
    private static final Map<String, BankAccount> accounts = new HashMap<>(); // Store user accounts

    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        bankKeyPair = keyGen.generateKeyPair();

        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(128);
        MasterSecret = aesKeyGen.generateKey();
        System.out.println("Bank Server is running...");

        ServerSocket serverSocket = new ServerSocket(PORT);
        while (true) {
            Socket socket = serverSocket.accept();
            new Thread(new ClientHandler(socket)).start();
        }
    }

    private static class ClientHandler implements Runnable {
        private Socket socket;
        private ObjectInputStream input;
        private ObjectOutputStream output;
        private PublicKey ATMpub;
        private String clientID;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                input = new ObjectInputStream(socket.getInputStream());
                output = new ObjectOutputStream(socket.getOutputStream());

                // Mutual Authentication
                ATMpub = (PublicKey) input.readObject();
                clientID = (String) input.readObject();
                clients.put(clientID, output);
                output.writeObject(bankKeyPair.getPublic());

                String NK = String.valueOf(new SecureRandom().nextInt(10000));
                output.writeObject(encryptRSA(ATMpub, NK + ".bankserver1"));

                String encryptedResponse = (String) input.readObject();
                String decryptedMessage = decryptRSA(bankKeyPair.getPrivate(), encryptedResponse);
                String[] parts = decryptedMessage.split("[.]");
                String clientNonce = parts[0];
                String receivedServerNonce = parts[1];
                
                if (!receivedServerNonce.equals(NK)) {
                    output.writeObject("Authentication failed. Invalid nonce.");
                    socket.close();
                    return;
                }
                
                output.writeObject(encryptRSA(ATMpub, clientNonce));
                output.writeObject(encryptRSA(ATMpub, Base64.getEncoder().encodeToString(MasterSecret.getEncoded())));

                System.out.println(clientID + " authenticated.");
                int counter = 1;

                // Password Handling
                boolean isReturningUser = accounts.containsKey(clientID);
                if (isReturningUser) {
                    output.writeObject("Welcome back, " + clientID + "!");
                    output.flush();
                                        while (true) {
                        output.writeObject("Please enter your password: ");
                        output.flush();
                        String enteredPassword = (String) input.readObject();

                        BankAccount account = accounts.get(clientID);
                        if (account.verifyPassword(enteredPassword)) {
                            output.writeObject("Login successful!");
                            output.flush();
                            break; // Exit password loop
                        } else if (counter == 3) {
                            socket.close();
                            break;
                            //return;
                        } else {
                            output.writeObject("Error: Incorrect password. Try again.");
                            output.flush();
                            counter+=1;
                        }
                    }
                } else {
                    output.writeObject("New account created for " + clientID + ".");
                    output.flush();
                    output.writeObject("Please create a password: ");
                    output.flush();
                    String password = (String) input.readObject();
                    accounts.put(clientID, new BankAccount(clientID, password));
                    output.writeObject("Account created successfully! You are now logged in.");
                    output.flush();
                }
                if (counter == 3) {
                    
                }else{
                // ATM Transaction Loop
                    while (true) {
                        try {
                            String receivedEncryptedMsg = (String) input.readObject();
                            String receivedMAC = (String) input.readObject();
                            String decryptedMsg = decryptMessage(MasterSecret, Base64.getDecoder().decode(receivedEncryptedMsg));
                            
                            String[] msgParts = decryptedMsg.split("::");

                            if (msgParts.length < 4) {
                                output.writeObject("Malformed message received.");
                                return;
                            }

                            String receivedClientID = msgParts[0];
                            String action = msgParts[1];
                            long timestamp = Long.parseLong(msgParts[2]);
//                            String signedMessage = msgParts[3];

                            // Check replay attack via timestamp
                            long currentTime = Instant.now().getEpochSecond();
                            long timeWindow = 300; // 300seconds

                            if (Math.abs(currentTime - timestamp) > timeWindow) {
                                output.writeObject("Timestamp too old or invalid. Possible replay attack.");
                                System.out.println("Rejected message from " + receivedClientID + " due to timestamp: " + timestamp);
                                return;
                            }

                            
                            if (!verifyMAC(decryptedMsg, receivedMAC, MasterSecret)) {
                                output.writeObject("MAC verification failed! Possible tampering detected.");
                                continue;
                            }

//                            String[] msgParts = decryptedMsg.split("::");
//                            String action = msgParts[1];

                            BankAccount account = accounts.get(clientID);
                            switch (action) {
                                case "1":
                                    String message = "Balance: $" + account.getBalance();
                                    System.out.println("Sending MESSAGE: \"" + message + "\" TO: " + account);
                                    output.writeObject(message);
                                    AuditLogger.logTransaction(clientID, "Balance Inquiry", -1, "Success");
                                    break;
                                case "2":
                                    output.writeObject("Enter deposit amount:");
                                    double depositAmount = Double.parseDouble((String) input.readObject());
                                    account.deposit(depositAmount);
                                    output.writeObject("Deposit successful. New balance: $" + account.getBalance());
                                    AuditLogger.logTransaction(clientID, "Deposit", depositAmount, "Success");
                                    break;
                                case "3":
                                    output.writeObject("Enter withdrawal amount:");
                                    double withdrawAmount = Double.parseDouble((String) input.readObject());
                                    if (account.withdraw(withdrawAmount)) {
                                        output.writeObject("Withdrawal successful. New balance: $" + account.getBalance());
                                        AuditLogger.logTransaction(clientID, "Withdrawal", withdrawAmount, "Success");
                                    } else {
                                        output.writeObject("Insufficient funds. Balance: $" + account.getBalance());
                                        AuditLogger.logTransaction(clientID, "Withdrawal", withdrawAmount, "Failed - Insufficient Funds");
                                    }
                                    break;
                                case "exit":
                                    output.writeObject("Logging out...");
                                    AuditLogger.logTransaction(clientID, "Logout", -1, "Success");
                                    break;
                                default:
                                    output.writeObject("Invalid action.");
                                    AuditLogger.logTransaction(clientID, "Invalid Action", -1, "Failed");
                            }

                        } catch (Exception e) {
                            System.out.println(clientID + " disconnected.");
                            clients.remove(clientID);
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
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

    private static String decryptMessage(SecretKey key, byte[] encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(encryptedMessage));
    }

    private static boolean verifyMAC(String message, String receivedMAC, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] expectedMAC = mac.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(expectedMAC).equals(receivedMAC);
    }
}
