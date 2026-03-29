package me.allync.ultimateauth.proxy;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

final class DatabaseManager implements AutoCloseable {
    private static final String UPSERT_ACCOUNT = """
            INSERT INTO ua_accounts (
                username_lower, last_name, player_uuid, premium_uuid, account_type, password_hash, password_algorithm,
                last_ip, last_server, last_login_at, registered_at, updated_at, session_ip, session_expires_at, migrated_from_jpremium
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                last_name = VALUES(last_name),
                player_uuid = VALUES(player_uuid),
                premium_uuid = VALUES(premium_uuid),
                account_type = VALUES(account_type),
                password_hash = VALUES(password_hash),
                password_algorithm = VALUES(password_algorithm),
                last_ip = VALUES(last_ip),
                last_server = VALUES(last_server),
                last_login_at = VALUES(last_login_at),
                registered_at = VALUES(registered_at),
                updated_at = VALUES(updated_at),
                session_ip = VALUES(session_ip),
                session_expires_at = VALUES(session_expires_at),
                migrated_from_jpremium = VALUES(migrated_from_jpremium)
            """;

    private final UltimateAuthPlugin plugin;
    private final PluginConfig config;
    private final PasswordService passwordService;
    private HikariDataSource dataSource;

    DatabaseManager(UltimateAuthPlugin plugin, PluginConfig config, PasswordService passwordService) {
        this.plugin = plugin;
        this.config = config;
        this.passwordService = passwordService;
    }

    void initialize() throws SQLException {
        PluginConfig.Storage storage = config.storage();

        HikariConfig hikariConfig = new HikariConfig();
        hikariConfig.setPoolName("UltimateAuth");
        hikariConfig.setDriverClassName("com.mysql.cj.jdbc.Driver");
        hikariConfig.setJdbcUrl("jdbc:mysql://" + storage.host() + ":" + storage.port() + "/" + storage.database()
                + "?useUnicode=true&characterEncoding=utf8&serverTimezone=UTC&useSSL=false&allowPublicKeyRetrieval=true");
        hikariConfig.setUsername(storage.user());
        hikariConfig.setPassword(storage.password());
        hikariConfig.setMaximumPoolSize(storage.maximumSize());
        hikariConfig.setMinimumIdle(storage.minimumIdle());
        hikariConfig.setConnectionTimeout(storage.connectionTimeoutMillis());
        hikariConfig.setMaxLifetime(storage.maxLifetimeMillis());
        hikariConfig.addDataSourceProperty("cachePrepStmts", "true");
        hikariConfig.addDataSourceProperty("prepStmtCacheSize", "250");
        hikariConfig.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
        for (String property : storage.properties()) {
            String[] split = property.split("=", 2);
            if (split.length == 2) {
                hikariConfig.addDataSourceProperty(split[0].trim(), split[1].trim());
            }
        }

        dataSource = new HikariDataSource(hikariConfig);
        createTables();
        new JPremiumFileImporter(plugin, this, config).importIfNeeded();
        migrateJPremiumIfNeeded();
    }

    Optional<AccountRecord> loadAccount(String playerName) {
        String usernameLower = normalizeName(playerName);
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT * FROM ua_accounts WHERE username_lower = ?")) {
            statement.setString(1, usernameLower);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return Optional.of(mapAccount(resultSet));
                }
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to load UltimateAuth account for " + playerName, exception);
        }
        return Optional.empty();
    }

    void saveAccount(AccountRecord account) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(UPSERT_ACCOUNT)) {
            bindAccount(statement, account);
            statement.executeUpdate();
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to save UltimateAuth account for " + account.getLastName(), exception);
        }
    }

    void saveMeta(String key, String value) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     INSERT INTO ua_meta (meta_key, meta_value) VALUES (?, ?)
                     ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)
                     """)) {
            statement.setString(1, key);
            statement.setString(2, value);
            statement.executeUpdate();
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to save UltimateAuth metadata " + key, exception);
        }
    }

    Optional<String> loadMeta(String key) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT meta_value FROM ua_meta WHERE meta_key = ?")) {
            statement.setString(1, key);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return Optional.ofNullable(resultSet.getString("meta_value"));
                }
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to load UltimateAuth metadata " + key, exception);
        }
        return Optional.empty();
    }

    AccountRecord newAccount(String playerName, UUID playerUuid) {
        AccountRecord account = new AccountRecord(normalizeName(playerName), playerName);
        account.setPlayerUuid(playerUuid);
        account.setUpdatedAt(System.currentTimeMillis());
        return account;
    }

    private void createTables() throws SQLException {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS ua_accounts (
                        username_lower VARCHAR(32) NOT NULL PRIMARY KEY,
                        last_name VARCHAR(32) NOT NULL,
                        player_uuid CHAR(36) NULL,
                        premium_uuid CHAR(36) NULL,
                        account_type VARCHAR(16) NOT NULL,
                        password_hash VARCHAR(255) NULL,
                        password_algorithm VARCHAR(16) NULL,
                        last_ip VARCHAR(64) NULL,
                        last_server VARCHAR(64) NULL,
                        last_login_at BIGINT NOT NULL DEFAULT 0,
                        registered_at BIGINT NOT NULL DEFAULT 0,
                        updated_at BIGINT NOT NULL DEFAULT 0,
                        session_ip VARCHAR(64) NULL,
                        session_expires_at BIGINT NOT NULL DEFAULT 0,
                        migrated_from_jpremium BOOLEAN NOT NULL DEFAULT FALSE
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                    """);
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS ua_meta (
                        meta_key VARCHAR(100) NOT NULL PRIMARY KEY,
                        meta_value VARCHAR(255) NOT NULL
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                    """);
        }
    }

    private void migrateJPremiumIfNeeded() throws SQLException {
        PluginConfig.Migration migration = config.migration();
        if (!migration.enabled()) {
            return;
        }
        if (migration.runOnce() && loadMeta("jpremium_migration_completed_at").isPresent()) {
            return;
        }

        try (Connection connection = dataSource.getConnection()) {
            if (!tableExists(connection, migration.sourceTable())) {
                plugin.getLogger().warning("JPremium migration skipped because table '" + migration.sourceTable() + "' was not found.");
                return;
            }

            String sql = "SELECT "
                    + identifier(migration.columns().username()) + ", "
                    + identifier(migration.columns().uniqueId()) + ", "
                    + identifier(migration.columns().premiumUniqueId()) + ", "
                    + identifier(migration.columns().passwordHash()) + ", "
                    + identifier(migration.columns().premium()) + ", "
                    + identifier(migration.columns().lastIp()) + ", "
                    + identifier(migration.columns().lastSeen())
                    + " FROM " + identifier(migration.sourceTable());

            int migrated = 0;
            try (PreparedStatement statement = connection.prepareStatement(sql);
                 ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    migrated += importAccount(new ImportedAccountData(
                            resultSet.getString(migration.columns().username()),
                            resultSet.getString(migration.columns().uniqueId()),
                            resultSet.getString(migration.columns().premiumUniqueId()),
                            resultSet.getString(migration.columns().passwordHash()),
                            resultSet.getObject(migration.columns().premium()),
                            resultSet.getString(migration.columns().lastIp()),
                            resultSet.getObject(migration.columns().lastSeen())
                    ), migration.defaultPasswordAlgorithm());
                }
            }

            if (migration.runOnce()) {
                saveMeta("jpremium_migration_completed_at", String.valueOf(System.currentTimeMillis()));
            }
            plugin.getLogger().info("UltimateAuth migrated " + migrated + " account(s) from JPremium.");
        } catch (SQLException exception) {
            throw new SQLException("Unable to migrate JPremium data: " + exception.getMessage(), exception);
        }
    }

    int importAccount(ImportedAccountData importedAccount, HashAlgorithm defaultPasswordAlgorithm) {
        String lastName = trimToNull(importedAccount.lastName());
        if (lastName == null) {
            return 0;
        }

        AccountRecord account = loadAccount(lastName).orElse(null);
        if (account == null) {
            account = newAccount(lastName, parseUuid(importedAccount.uniqueId()));
        }

        account.setLastName(lastName);
        account.setPlayerUuid(parseUuid(importedAccount.uniqueId()));
        account.setPremiumUuid(parseUuid(importedAccount.premiumUniqueId()));
        if (isBedrockUsername(lastName)) {
            account.setAccountType(AccountType.BEDROCK);
        } else {
            account.setAccountType(parseBooleanLike(importedAccount.premiumValue()) ? AccountType.PREMIUM : AccountType.CRACKED);
        }

        String passwordHash = trimToNull(importedAccount.passwordHash());
        if (passwordHash != null) {
            account.setPasswordHash(passwordService.normalizeImportedHash(passwordHash, defaultPasswordAlgorithm));
            account.setPasswordAlgorithm(passwordService.detectAlgorithm(account.getPasswordHash(), defaultPasswordAlgorithm));
        }

        account.setLastIp(trimToNull(importedAccount.lastIp()));
        long lastSeen = parseEpoch(importedAccount.lastSeenValue());
        account.setLastLoginAt(lastSeen);
        if (account.getRegisteredAt() == 0 && account.hasPassword()) {
            account.setRegisteredAt(lastSeen > 0 ? lastSeen : System.currentTimeMillis());
        }
        account.setMigratedFromJPremium(true);
        account.setUpdatedAt(System.currentTimeMillis());
        saveAccount(account);
        return 1;
    }

    private boolean tableExists(Connection connection, String tableName) throws SQLException {
        DatabaseMetaData metaData = connection.getMetaData();
        try (ResultSet resultSet = metaData.getTables(connection.getCatalog(), null, tableName, new String[]{"TABLE"})) {
            return resultSet.next();
        }
    }

    private void bindAccount(PreparedStatement statement, AccountRecord account) throws SQLException {
        statement.setString(1, account.getUsernameLower());
        statement.setString(2, account.getLastName());
        statement.setString(3, uuidString(account.getPlayerUuid()));
        statement.setString(4, uuidString(account.getPremiumUuid()));
        statement.setString(5, account.getAccountType().name());
        statement.setString(6, account.getPasswordHash());
        statement.setString(7, account.getPasswordAlgorithm() == null ? null : account.getPasswordAlgorithm().name());
        statement.setString(8, account.getLastIp());
        statement.setString(9, account.getLastServer());
        statement.setLong(10, account.getLastLoginAt());
        statement.setLong(11, account.getRegisteredAt());
        statement.setLong(12, account.getUpdatedAt());
        statement.setString(13, account.getSessionIp());
        statement.setLong(14, account.getSessionExpiresAt());
        statement.setBoolean(15, account.isMigratedFromJPremium());
    }

    private AccountRecord mapAccount(ResultSet resultSet) throws SQLException {
        AccountRecord account = new AccountRecord(
                resultSet.getString("username_lower"),
                resultSet.getString("last_name")
        );
        account.setPlayerUuid(parseUuid(resultSet.getString("player_uuid")));
        account.setPremiumUuid(parseUuid(resultSet.getString("premium_uuid")));
        account.setAccountType(AccountType.valueOf(resultSet.getString("account_type").toUpperCase(Locale.ROOT)));
        account.setPasswordHash(trimToNull(resultSet.getString("password_hash")));
        account.setPasswordAlgorithm(HashAlgorithm.from(resultSet.getString("password_algorithm"), HashAlgorithm.SHA256));
        account.setLastIp(trimToNull(resultSet.getString("last_ip")));
        account.setLastServer(trimToNull(resultSet.getString("last_server")));
        account.setLastLoginAt(resultSet.getLong("last_login_at"));
        account.setRegisteredAt(resultSet.getLong("registered_at"));
        account.setUpdatedAt(resultSet.getLong("updated_at"));
        account.setSessionIp(trimToNull(resultSet.getString("session_ip")));
        account.setSessionExpiresAt(resultSet.getLong("session_expires_at"));
        account.setMigratedFromJPremium(resultSet.getBoolean("migrated_from_jpremium"));
        if (account.hasPassword()) {
            account.setPasswordAlgorithm(passwordService.detectAlgorithm(account.getPasswordHash(), account.getPasswordAlgorithm()));
        }
        return account;
    }

    private String identifier(String value) {
        return "`" + value.replace("`", "") + "`";
    }

    private String uuidString(UUID uuid) {
        return uuid == null ? null : uuid.toString();
    }

    private UUID parseUuid(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException ignored) {
            String normalized = value.replaceFirst(
                    "(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)",
                    "$1-$2-$3-$4-$5"
            );
            try {
                return UUID.fromString(normalized);
            } catch (IllegalArgumentException exception) {
                return null;
            }
        }
    }

    private String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private boolean parseBooleanLike(Object value) {
        if (value == null) {
            return false;
        }
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof Number number) {
            return number.intValue() != 0;
        }
        String text = value.toString().trim().toLowerCase(Locale.ROOT);
        if (text.isEmpty() || text.equals("0") || text.equals("false") || text.equals("no") || text.equals("null")) {
            return false;
        }
        return true;
    }

    private long parseEpoch(Object value) {
        if (value == null) {
            return 0L;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof Timestamp timestamp) {
            return timestamp.getTime();
        }
        if (value instanceof java.util.Date date) {
            return date.getTime();
        }
        if (value instanceof Instant instant) {
            return instant.toEpochMilli();
        }
        String text = value.toString().trim();
        if (text.isEmpty()) {
            return 0L;
        }
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException ignored) {
            try {
                return Timestamp.valueOf(text).getTime();
            } catch (IllegalArgumentException timestampException) {
                try {
                    return Timestamp.valueOf(LocalDateTime.parse(text, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).getTime();
                } catch (Exception ignoredAgain) {
                    return 0L;
                }
            }
        }
    }

    static String normalizeName(String playerName) {
        return playerName.toLowerCase(Locale.ROOT);
    }

    private boolean isBedrockUsername(String playerName) {
        if (!config.bedrock().enabled()) {
            return false;
        }
        String normalized = playerName.toLowerCase(Locale.ROOT);
        for (String prefix : config.bedrock().autoLoginPrefixes()) {
            if (!prefix.isBlank() && normalized.startsWith(prefix.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void close() {
        if (dataSource != null) {
            dataSource.close();
        }
    }
}
