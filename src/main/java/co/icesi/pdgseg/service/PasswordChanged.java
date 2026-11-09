package co.icesi.pdgseg.service;

/**
 * Published when a password is changed with a reset link, so the owner of the account learns about
 * it even if someone else did it.
 */
public record PasswordChanged(String username, String email) {}
