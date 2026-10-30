package com.csrfshield.model;

public class User {
    private final String username;
    private final String passwordHash;
    private double balance;
    private String email;

    public User(String username, String passwordHash, double balance, String email) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.balance = balance;
        this.email = email;
    }

    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public double getBalance() { return balance; }
    public void setBalance(double balance) { this.balance = balance; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}
