/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package backend;

/**
 *
 * @author marcusuy
 */

import java.util.HashMap;

public class SecureBankClient {
    private HashMap<String, BankAccount> accounts;
    private BankAccount currentAccount;

    public SecureBankClient() {
        accounts = new HashMap<>();
        
        // Hardcoded users (for testing/demo)
        accounts.put("marcus", new BankAccount("marcus", "1234"));
        accounts.put("alice", new BankAccount("alice", "5678"));
    }

    public boolean login(String userID, String password) {
        BankAccount account = accounts.get(userID);
        if (account != null && account.verifyPassword(password)) {
            currentAccount = account;
            return true;
        }
        return false;
    }

    public void logout() {
        currentAccount = null;
    }

    public String checkBalance() {
        if (currentAccount == null) return "Not logged in.";
        return "Your balance is: $" + String.format("%.2f", currentAccount.getBalance());
    }

    public String deposit(double amount) {
        if (currentAccount == null) return "Not logged in.";
        currentAccount.deposit(amount);
        return "Deposited $" + String.format("%.2f", amount);
    }

    public String withdraw(double amount) {
        if (currentAccount == null) return "Not logged in.";
        boolean success = currentAccount.withdraw(amount);
        if (success) {
            return "Withdrew $" + String.format("%.2f", amount);
        } else {
            return "Insufficient funds.";
        }
    }

    public boolean isLoggedIn() {
        return currentAccount != null;
    }

    public String getLoggedInUser() {
        return currentAccount != null ? currentAccount.toString() : "None";
    }
}

