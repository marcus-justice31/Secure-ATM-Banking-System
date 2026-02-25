package frontend;

/**
 *
 * @author marcusuy
 */

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.time.Instant;

public class ATMInterface extends JFrame {
    private static final int serverPort = 12345;
    private static SecretKey masterSecret;

    private JTextField clientIDField, amountField;
    private JPasswordField passwordField;
    private JTextArea outputArea;
    private PrivateKey clientPrivateKey;
    private PublicKey bankPublicKey;
    private Socket socket;
    private ObjectOutputStream output;
    private ObjectInputStream input;

    public ATMInterface() {
        setTitle("Secure ATM");
        setSize(400, 500);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        // Login Panel
        JPanel loginPanel = new JPanel(new GridLayout(3, 2));
        clientIDField = new JTextField();
        passwordField = new JPasswordField();

        loginPanel.add(new JLabel("Client ID:"));
        loginPanel.add(clientIDField);
        loginPanel.add(new JLabel("Password:"));
        loginPanel.add(passwordField);

        JButton loginButton = new JButton("Login");
        loginPanel.add(loginButton);
        add(loginPanel, BorderLayout.NORTH);

        // Output Area
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        add(new JScrollPane(outputArea), BorderLayout.CENTER);

        // Buttons for operations
        JPanel buttonPanel = new JPanel();
        JButton balanceBtn = new JButton("Check Balance");
        JButton depositBtn = new JButton("Deposit");
        JButton withdrawBtn = new JButton("Withdraw");
        JButton logoutBtn = new JButton("Logout");

        amountField = new JTextField(10);

        buttonPanel.add(balanceBtn);
        buttonPanel.add(new JLabel("Amount:"));
        buttonPanel.add(amountField);
        buttonPanel.add(depositBtn);
        buttonPanel.add(withdrawBtn);
        buttonPanel.add(logoutBtn);

        add(buttonPanel, BorderLayout.SOUTH);

        // Button Actions
        loginButton.addActionListener(e -> {
            String clientID = clientIDField.getText();
            String password = new String(passwordField.getPassword());
            try {
                connectToServer(clientID, password);
            } catch (Exception ex) {
                outputArea.append("Error: " + ex.getMessage() + "\n");
            }
        });

        balanceBtn.addActionListener(e -> {
            try {
                checkBalance();
            } catch (Exception ex) {
                outputArea.append("Error: " + ex.getMessage() + "\n");
            }
        });

        depositBtn.addActionListener(e -> {
            try {
                String amount = amountField.getText();
                deposit(Double.parseDouble(amount));
            } catch (Exception ex) {
                outputArea.append("Error: " + ex.getMessage() + "\n");
            }
        });

        withdrawBtn.addActionListener(e -> {
            try {
                String amount = amountField.getText();
                withdraw(Double.parseDouble(amount));
            } catch (Exception ex) {
                outputArea.append("Error: " + ex.getMessage() + "\n");
            }
        });

        logoutBtn.addActionListener(e -> {
            try {
                logout();
            } catch (Exception ex) {
                outputArea.append("Error: " + ex.getMessage() + "\n");
            }
        });

        setVisible(true);
    }

    private void connectToServer(String clientID, String password) throws Exception {
        // Generate RSA Keypair for client
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair clientKeyPair = keyGen.generateKeyPair();
        clientPrivateKey = clientKeyPair.getPrivate();

        // Connect to server
        socket = new Socket("localhost", serverPort);
        output = new ObjectOutputStream(socket.getOutputStream());
        input = new ObjectInputStream(socket.getInputStream());

        //------------------------ Mutual Authentication start------------------------------------------------

        // Send public key & client ID
        output.writeObject(clientKeyPair.getPublic());
        output.writeObject(clientID);

        bankPublicKey = (PublicKey) input.readObject();
        String encryptedResponse = (String) input.readObject();
        String decryptedMessage = decryptRSA(clientPrivateKey, encryptedResponse);
        String[] parts = decryptedMessage.split("[.]");
        String NK1 = parts[0];
        String serverID = parts[1];

        outputArea.append("... validating connection with server " + serverID + "\n");

        // Send response nonce
        String NA = String.valueOf(new SecureRandom().nextInt(10000));
        String encryptedMessage = encryptRSA(bankPublicKey, NA + "." + NK1);
        output.writeObject(encryptedMessage);

        // Receive confirmation nonce
        String encConfirmation = (String) input.readObject();
        String confirmation = decryptRSA(clientPrivateKey, encConfirmation);
        if (!confirmation.equals(NA)) {
            outputArea.append("Nonce verification failed for bank server\n");
            socket.close();
            return;  // Restart the login process
        } else {
            outputArea.append("Secure connection to bank server established. Verifying credentials for " + clientID + "...\n");
        }

        //------------------------ Mutual Authentication end------------------------------------------------

        //------------------------ Receive MS key ------------------------------------------------
        String encryptedMasterSecret = (String) input.readObject();
        byte[] decodedKey = Base64.getDecoder().decode(decryptRSA(clientPrivateKey, encryptedMasterSecret));
        masterSecret = new SecretKeySpec(decodedKey, "AES");

        // Receive and print welcome message
        String welcomeMessage = (String) input.readObject();
        outputArea.append("Server: " + welcomeMessage + "\n");

        //------------------------ Handle Password Prompt and Errors ------------------------------
        handlePasswordPrompt(clientID, password);
    }

    private void handlePasswordPrompt(String clientID, String password) throws Exception {
        int counter = 0;
        while (true) {
            // Request for password prompt
            String passwordPrompt = (String) input.readObject();
            outputArea.append("Server: " + passwordPrompt + "\n");

            // Send the password for verification
            output.writeObject(password);

            // Receive the server's response
            String response = (String) input.readObject();
            outputArea.append("Server: " + response + "\n");

            if (response.equals("Login successful!") || response.contains("Account created successfully")) {
                // Only show success message after the password is successfully verified
                outputArea.append("Login successful! Welcome, " + clientID + ".\n");
                clientIDField.setText("");
                passwordField.setText("");
                break;  // Exit password loop, enter main transaction loop
            } else if (counter == 2) {
                // If 2 attempts failed, close the connection and terminate
                outputArea.append("Error: Too many failed attempts. Connection closed.\n");
                socket.close();
                return;
            } else {
                // If password is incorrect, notify the user and count the attempt
                outputArea.append("Incorrect password. Please try again. (Connection will terminate after 2 attempts)\n");
                counter++;
                outputArea.append("Attempt " + counter + "/2 failed\n");
            }
        }
    }

    private void checkBalance() throws Exception {
        // Assume clientID is already defined as part of the login process
        String message = "1"; // Balance action (can be extended to deposit, withdraw, etc.)

        // Check if the message is a valid action
        if (message.equals("1") || message.equals("2") || message.equals("3")) {
            // Get the current timestamp (used for replay protection)
            long timestamp = Instant.now().getEpochSecond();

            // Sign the message with the client's private key
            String signedMessage = signMessage(clientIDField.getText() + "::" + message + "::" + timestamp, clientPrivateKey);

            // Combine clientID, message, timestamp, and signed message
            String finalMessage = clientIDField.getText() + "::" + message + "::" + timestamp + "::" + signedMessage;

            // Generate MAC for the message using the master secret (HMAC or any MAC generation method)
            String mac = generateMAC(finalMessage, masterSecret);

            // Encrypt the final message using the master secret
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptMessage(masterSecret, finalMessage));

            // Send the encrypted message and MAC to the server
            output.writeObject(encryptedMessage);
            output.writeObject(mac);

            // Receive server response (balance or error message)
            String serverResponse = (String) input.readObject();
            System.out.println("Server: " + serverResponse);

            // Optionally, display the server's response in the UI (outputArea)
            outputArea.append("Server: " + serverResponse + "\n");
        } else {
            System.out.println("Invalid action.");
            outputArea.append("Invalid action.\n");
        }
    }

    private void deposit(double amount) throws Exception {
        if (amount < 0) {
            outputArea.append("Error: Amount cannot be negative.\n");
            return;
        }
        String message = "2"; // Deposit action

        if (message.equals("2") || message.equals("3")) {
            // Get the current timestamp (for replay protection)
            long timestamp = Instant.now().getEpochSecond();

            // Sign the message with the client's private key
            String signedMessage = signMessage(clientIDField.getText() + "::" + message + "::" + timestamp, clientPrivateKey);

            // Combine clientID, message, timestamp, and signed message
            String finalMessage = clientIDField.getText() + "::" + message + "::" + timestamp + "::" + signedMessage;

            // Generate MAC for the message using the master secret
            String mac = generateMAC(finalMessage, masterSecret);

            // Encrypt the final message using the master secret
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptMessage(masterSecret, finalMessage));

            // Send the encrypted message and MAC to the server
            output.writeObject(encryptedMessage);
            output.writeObject(mac);

            // Receive server response (balance or error message)
            String serverResponse = (String) input.readObject();
            System.out.println("Server: " + serverResponse);

            // Send the amount for deposit
            output.writeObject(String.valueOf(amount));

            // Receive transaction result from the server
            String transactionResult = (String) input.readObject();
            outputArea.append("Deposit result: " + transactionResult + "\n");
            amountField.setText("");
            
        } else {
            outputArea.append("Invalid action.\n");
        }
    }
    
    private void withdraw(double amount) throws Exception {
        if (amount < 0) {
            outputArea.append("Error: Amount cannot be negative.\n");
            return;
        }
        
        String message = "3"; // Withdraw action

        if (message.equals("2") || message.equals("3")) {
            // Get the current timestamp (for replay protection)
            long timestamp = Instant.now().getEpochSecond();

            // Sign the message with the client's private key
            String signedMessage = signMessage(clientIDField.getText() + "::" + message + "::" + timestamp, clientPrivateKey);

            // Combine clientID, message, timestamp, and signed message
            String finalMessage = clientIDField.getText() + "::" + message + "::" + timestamp + "::" + signedMessage;

            // Generate MAC for the message using the master secret
            String mac = generateMAC(finalMessage, masterSecret);

            // Encrypt the final message using the master secret
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptMessage(masterSecret, finalMessage));

            // Send the encrypted message and MAC to the server
            output.writeObject(encryptedMessage);
            output.writeObject(mac);

            // Receive server response (balance or error message)
            String serverResponse = (String) input.readObject();
            System.out.println("Server: " + serverResponse);

            // Send the amount for withdrawal
            output.writeObject(String.valueOf(amount));

            // Receive transaction result from the server
            String transactionResult = (String) input.readObject();
            outputArea.append("Withdrawal result: " + transactionResult + "\n");
            amountField.setText("");
        } else {
            outputArea.append("Invalid action.\n");
        }
    }


    private void logout() throws Exception {
        output.writeObject("exit");
        socket.close();
        outputArea.append("Logged out.\n");
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

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new ATMInterface());
    }
}
