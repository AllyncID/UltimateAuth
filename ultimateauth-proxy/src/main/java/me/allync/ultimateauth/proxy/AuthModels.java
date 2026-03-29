package me.allync.ultimateauth.proxy;

import net.md_5.bungee.api.scheduler.ScheduledTask;

import java.util.UUID;

enum AccountType {
    PREMIUM,
    CRACKED,
    BEDROCK
}

enum PremiumUuidMode {
    LEGACY,
    REAL;

    static PremiumUuidMode from(String value, PremiumUuidMode fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        for (PremiumUuidMode mode : values()) {
            if (mode.name().equalsIgnoreCase(value.trim())) {
                return mode;
            }
        }
        return fallback;
    }
}

enum HashAlgorithm {
    SHA256("SHA-256"),
    SHA512("SHA-512"),
    BCRYPT("BCRYPT");

    private final String digestName;

    HashAlgorithm(String digestName) {
        this.digestName = digestName;
    }

    String digestName() {
        return digestName;
    }

    static HashAlgorithm from(String value, HashAlgorithm fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        for (HashAlgorithm algorithm : values()) {
            if (algorithm.name().equalsIgnoreCase(value.trim())) {
                return algorithm;
            }
        }
        return fallback;
    }
}

enum AuthStatus {
    LOADING,
    LOGIN_REQUIRED,
    REGISTER_REQUIRED,
    AUTHORIZED
}

final class AccountRecord {
    private final String usernameLower;
    private String lastName;
    private UUID playerUuid;
    private UUID premiumUuid;
    private AccountType accountType;
    private String passwordHash;
    private HashAlgorithm passwordAlgorithm;
    private String lastIp;
    private String lastServer;
    private long lastLoginAt;
    private long registeredAt;
    private long updatedAt;
    private String sessionIp;
    private long sessionExpiresAt;
    private boolean migratedFromJPremium;

    AccountRecord(String usernameLower, String lastName) {
        this.usernameLower = usernameLower;
        this.lastName = lastName;
        this.accountType = AccountType.CRACKED;
        this.passwordAlgorithm = HashAlgorithm.SHA256;
    }

    AccountRecord copy() {
        AccountRecord copy = new AccountRecord(usernameLower, lastName);
        copy.playerUuid = playerUuid;
        copy.premiumUuid = premiumUuid;
        copy.accountType = accountType;
        copy.passwordHash = passwordHash;
        copy.passwordAlgorithm = passwordAlgorithm;
        copy.lastIp = lastIp;
        copy.lastServer = lastServer;
        copy.lastLoginAt = lastLoginAt;
        copy.registeredAt = registeredAt;
        copy.updatedAt = updatedAt;
        copy.sessionIp = sessionIp;
        copy.sessionExpiresAt = sessionExpiresAt;
        copy.migratedFromJPremium = migratedFromJPremium;
        return copy;
    }

    String getUsernameLower() {
        return usernameLower;
    }

    String getLastName() {
        return lastName;
    }

    void setLastName(String lastName) {
        this.lastName = lastName;
    }

    UUID getPlayerUuid() {
        return playerUuid;
    }

    void setPlayerUuid(UUID playerUuid) {
        this.playerUuid = playerUuid;
    }

    UUID getPremiumUuid() {
        return premiumUuid;
    }

    void setPremiumUuid(UUID premiumUuid) {
        this.premiumUuid = premiumUuid;
    }

    AccountType getAccountType() {
        return accountType;
    }

    void setAccountType(AccountType accountType) {
        this.accountType = accountType;
    }

    String getPasswordHash() {
        return passwordHash;
    }

    void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    HashAlgorithm getPasswordAlgorithm() {
        return passwordAlgorithm;
    }

    void setPasswordAlgorithm(HashAlgorithm passwordAlgorithm) {
        this.passwordAlgorithm = passwordAlgorithm;
    }

    String getLastIp() {
        return lastIp;
    }

    void setLastIp(String lastIp) {
        this.lastIp = lastIp;
    }

    String getLastServer() {
        return lastServer;
    }

    void setLastServer(String lastServer) {
        this.lastServer = lastServer;
    }

    long getLastLoginAt() {
        return lastLoginAt;
    }

    void setLastLoginAt(long lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    long getRegisteredAt() {
        return registeredAt;
    }

    void setRegisteredAt(long registeredAt) {
        this.registeredAt = registeredAt;
    }

    long getUpdatedAt() {
        return updatedAt;
    }

    void setUpdatedAt(long updatedAt) {
        this.updatedAt = updatedAt;
    }

    String getSessionIp() {
        return sessionIp;
    }

    void setSessionIp(String sessionIp) {
        this.sessionIp = sessionIp;
    }

    long getSessionExpiresAt() {
        return sessionExpiresAt;
    }

    void setSessionExpiresAt(long sessionExpiresAt) {
        this.sessionExpiresAt = sessionExpiresAt;
    }

    boolean isMigratedFromJPremium() {
        return migratedFromJPremium;
    }

    void setMigratedFromJPremium(boolean migratedFromJPremium) {
        this.migratedFromJPremium = migratedFromJPremium;
    }

    boolean hasPassword() {
        return passwordHash != null && !passwordHash.isBlank();
    }

    boolean hasValidSession(String ipAddress, long now) {
        return sessionIp != null
                && sessionIp.equalsIgnoreCase(ipAddress)
                && sessionExpiresAt > now;
    }
}

final class AuthSession {
    private final UUID uniqueId;
    private volatile String lastKnownName;
    private volatile AccountRecord account;
    private volatile AuthStatus status = AuthStatus.LOADING;
    private volatile int failedLoginAttempts;
    private volatile long authDeadlineAt;
    private volatile ScheduledTask reminderTask;
    private volatile ScheduledTask timeoutTask;
    private volatile String joinMessageKey;
    private volatile String joinTitleKey;

    AuthSession(UUID uniqueId, String lastKnownName) {
        this.uniqueId = uniqueId;
        this.lastKnownName = lastKnownName;
    }

    UUID getUniqueId() {
        return uniqueId;
    }

    String getLastKnownName() {
        return lastKnownName;
    }

    void setLastKnownName(String lastKnownName) {
        this.lastKnownName = lastKnownName;
    }

    AccountRecord getAccount() {
        return account;
    }

    void setAccount(AccountRecord account) {
        this.account = account;
    }

    AuthStatus getStatus() {
        return status;
    }

    void setStatus(AuthStatus status) {
        this.status = status;
    }

    int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
    }

    int incrementFailedLoginAttempts() {
        return ++failedLoginAttempts;
    }

    long getAuthDeadlineAt() {
        return authDeadlineAt;
    }

    void setAuthDeadlineAt(long authDeadlineAt) {
        this.authDeadlineAt = authDeadlineAt;
    }

    ScheduledTask getReminderTask() {
        return reminderTask;
    }

    void setReminderTask(ScheduledTask reminderTask) {
        this.reminderTask = reminderTask;
    }

    ScheduledTask getTimeoutTask() {
        return timeoutTask;
    }

    void setTimeoutTask(ScheduledTask timeoutTask) {
        this.timeoutTask = timeoutTask;
    }

    String getJoinMessageKey() {
        return joinMessageKey;
    }

    void setJoinMessageKey(String joinMessageKey) {
        this.joinMessageKey = joinMessageKey;
    }

    String getJoinTitleKey() {
        return joinTitleKey;
    }

    void setJoinTitleKey(String joinTitleKey) {
        this.joinTitleKey = joinTitleKey;
    }

    boolean isAuthorized() {
        return status == AuthStatus.AUTHORIZED;
    }

    boolean requiresAuth() {
        return status == AuthStatus.LOGIN_REQUIRED || status == AuthStatus.REGISTER_REQUIRED;
    }

    void cancelTasks() {
        if (reminderTask != null) {
            reminderTask.cancel();
            reminderTask = null;
        }
        if (timeoutTask != null) {
            timeoutTask.cancel();
            timeoutTask = null;
        }
    }
}

record PremiumProfile(UUID uuid) {
}

enum PremiumLookupStatus {
    FOUND,
    NOT_FOUND,
    ERROR
}

record PremiumLookupResult(PremiumLookupStatus status, PremiumProfile profile) {
    boolean found() {
        return status == PremiumLookupStatus.FOUND && profile != null;
    }

    static PremiumLookupResult found(PremiumProfile profile) {
        return new PremiumLookupResult(PremiumLookupStatus.FOUND, profile);
    }

    static PremiumLookupResult notFound() {
        return new PremiumLookupResult(PremiumLookupStatus.NOT_FOUND, null);
    }

    static PremiumLookupResult error() {
        return new PremiumLookupResult(PremiumLookupStatus.ERROR, null);
    }
}

record PreparedLogin(AccountRecord account, AuthStatus status, String joinMessageKey, String joinTitleKey) {
}

record ImportedAccountData(String lastName,
                           String uniqueId,
                           String premiumUniqueId,
                           String passwordHash,
                           Object premiumValue,
                           String lastIp,
                           Object lastSeenValue) {
}
