package me.allync.ultimateauth.proxy;

import org.mindrot.jbcrypt.BCrypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

final class PasswordService {
    private final SecureRandom secureRandom = new SecureRandom();

    String hash(String password, HashAlgorithm algorithm) {
        return switch (algorithm) {
            case SHA256, SHA512 -> legacyHash(password, algorithm, randomSalt());
            case BCRYPT -> "BCRYPT$" + BCrypt.hashpw(password, BCrypt.gensalt(12));
        };
    }

    boolean matches(String password, AccountRecord account) {
        return matches(password, account.getPasswordHash(), account.getPasswordAlgorithm());
    }

    boolean matches(String password, String storedHash, HashAlgorithm fallback) {
        if (storedHash == null || storedHash.isBlank()) {
            return false;
        }

        HashAlgorithm algorithm = detectAlgorithm(storedHash, fallback);
        return switch (algorithm) {
            case SHA256, SHA512 -> verifyLegacy(password, normalizeImportedHash(storedHash, algorithm), algorithm);
            case BCRYPT -> {
                String bcryptHash = storedHash.startsWith("BCRYPT$") ? storedHash.substring("BCRYPT$".length()) : storedHash;
                yield BCrypt.checkpw(password, bcryptHash);
            }
        };
    }

    HashAlgorithm detectAlgorithm(String storedHash, HashAlgorithm fallback) {
        if (storedHash == null || storedHash.isBlank()) {
            return fallback;
        }
        if (storedHash.startsWith("SHA256$")) {
            return HashAlgorithm.SHA256;
        }
        if (storedHash.startsWith("SHA512$")) {
            return HashAlgorithm.SHA512;
        }
        if (storedHash.startsWith("BCRYPT$") || storedHash.startsWith("$2a$")
                || storedHash.startsWith("$2b$") || storedHash.startsWith("$2y$")) {
            return HashAlgorithm.BCRYPT;
        }
        return fallback;
    }

    String normalizeImportedHash(String storedHash, HashAlgorithm fallback) {
        if (storedHash == null || storedHash.isBlank()) {
            return storedHash;
        }
        if (storedHash.startsWith("SHA256$") || storedHash.startsWith("SHA512$") || storedHash.startsWith("BCRYPT$")) {
            return storedHash;
        }
        if (storedHash.startsWith("$2a$") || storedHash.startsWith("$2b$") || storedHash.startsWith("$2y$")) {
            return "BCRYPT$" + storedHash;
        }
        if (storedHash.contains("$") && fallback != HashAlgorithm.BCRYPT) {
            return fallback.name() + "$" + storedHash;
        }
        return storedHash;
    }

    private boolean verifyLegacy(String password, String storedHash, HashAlgorithm algorithm) {
        String[] parts = storedHash.split("\\$", 3);
        if (parts.length != 3) {
            return false;
        }

        String expected = legacyHash(password, algorithm, parts[1]).split("\\$", 3)[2];
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), parts[2].getBytes(StandardCharsets.UTF_8));
    }

    private String legacyHash(String password, HashAlgorithm algorithm, String salt) {
        String firstPass = hex(digest(password, algorithm));
        String secondPass = hex(digest(firstPass + salt, algorithm));
        return algorithm.name() + "$" + salt + "$" + secondPass;
    }

    private byte[] digest(String value, HashAlgorithm algorithm) {
        try {
            return MessageDigest.getInstance(algorithm.digestName()).digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Missing digest algorithm " + algorithm.digestName(), exception);
        }
    }

    private String randomSalt() {
        byte[] bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        return hex(bytes);
    }

    private String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }
}
