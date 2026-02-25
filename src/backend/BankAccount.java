package backend;

/**
 *
 * @author marcusuy
 */
// BankAccount class (Object to store user balance and transactions)
class BankAccount {
    private String userID;
    private double balance;
    private String password;

    public BankAccount(String userID, String password) {
        this.userID = userID;
        this.balance = 0.0;
        this.password = password;
    }

    public synchronized void deposit(double amount) {
        balance += amount;
    }

    public synchronized boolean withdraw(double amount) {
        if (amount > balance) return false;
        balance -= amount;
        return true;
    }

    public synchronized double getBalance() {
        return balance;
    }
    
    public boolean verifyPassword(String inputPassword) {
        return this.password.equals(inputPassword);
    }
}
