package me.allync.ultimateauth.proxy;

import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;
import net.md_5.bungee.config.YamlConfiguration;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

final class PluginConfig {
    private final Storage storage;
    private final Network network;
    private final Premium premium;
    private final Bedrock bedrock;
    private final Authorization authorization;
    private final Visuals visuals;
    private final BackendBridge backendBridge;
    private final Migration migration;

    private PluginConfig(Storage storage,
                         Network network,
                         Premium premium,
                         Bedrock bedrock,
                         Authorization authorization,
                         Visuals visuals,
                         BackendBridge backendBridge,
                         Migration migration) {
        this.storage = storage;
        this.network = network;
        this.premium = premium;
        this.bedrock = bedrock;
        this.authorization = authorization;
        this.visuals = visuals;
        this.backendBridge = backendBridge;
        this.migration = migration;
    }

    static PluginConfig load(File file) throws IOException {
        Configuration root = ConfigurationProvider.getProvider(YamlConfiguration.class).load(file);

        Configuration storageSection = root.getSection("storage");
        Configuration poolSection = storageSection.getSection("pool");
        Configuration networkSection = root.getSection("network");
        Configuration premiumSection = root.getSection("premium");
        Configuration bedrockSection = root.getSection("bedrock");
        Configuration authSection = root.getSection("authorization");
        Configuration visualsSection = root.getSection("visuals");
        Configuration bridgeSection = root.getSection("backendBridge");
        Configuration migrationSection = root.getSection("migration.jpremium");
        Configuration fileImportSection = migrationSection.getSection("fileImport");
        Configuration columnsSection = migrationSection.getSection("columns");

        Storage storage = new Storage(
                storageSection.getString("host"),
                storageSection.getInt("port"),
                storageSection.getString("database"),
                storageSection.getString("user"),
                storageSection.getString("password"),
                storageSection.getStringList("properties"),
                poolSection.getInt("maximumSize"),
                poolSection.getInt("minimumIdle"),
                poolSection.getLong("connectionTimeoutMillis"),
                poolSection.getLong("maxLifetimeMillis")
        );

        Network network = new Network(
                networkSection.getString("accessToken"),
                normalizeSet(networkSection.getStringList("acceptedHostnames")),
                normalizeList(networkSection.getStringList("limboServers")),
                normalizeList(networkSection.getStringList("mainServers")),
                networkSection.getBoolean("rememberLastServer"),
                networkSection.getBoolean("redirectOnKick")
        );

        Premium premium = new Premium(
                premiumSection.getBoolean("autoDetectNames"),
                premiumSection.getBoolean("registerPremiumUsers"),
                premiumSection.getBoolean("protectUnregisteredNames"),
                PremiumUuidMode.from(premiumSection.getString("existingPremiumUuidMode"), PremiumUuidMode.LEGACY)
        );

        Bedrock bedrock = new Bedrock(
                bedrockSection.getBoolean("enabled"),
                normalizeList(bedrockSection.getStringList("autoLoginPrefixes"))
        );

        Authorization authorization = new Authorization(
                HashAlgorithm.from(authSection.getString("defaultHashingAlgorithm"), HashAlgorithm.SHA256),
                authSection.getString("safePasswordPattern"),
                authSection.getInt("maximumLoginTriesBeforeDisconnection"),
                authSection.getInt("maximumAuthorisationTimeSeconds"),
                authSection.getInt("automaticSessionTimeMinutes"),
                normalizeSet(authSection.getStringList("logoutUserCommands")),
                normalizeList(authSection.getStringList("loginAliases"))
        );

        Visuals visuals = new Visuals(
                visualsSection.getLong("delayTitlesAfterJoinMillis"),
                visualsSection.getInt("reminderIntervalSeconds")
        );

        BackendBridge backendBridge = new BackendBridge(
                bridgeSection.getBoolean("enabled"),
                bridgeSection.getString("pluginChannel")
        );

        Migration migration = new Migration(
                migrationSection.getBoolean("enabled"),
                migrationSection.getBoolean("runOnce"),
                migrationSection.getString("sourceTable"),
                HashAlgorithm.from(migrationSection.getString("defaultPasswordAlgorithm"), HashAlgorithm.SHA256),
                new FileImport(
                        fileImportSection.getBoolean("enabled"),
                        fileImportSection.getBoolean("runOnce"),
                        fileImportSection.getString("directory"),
                        fileImportSection.getString("fileName")
                ),
                new MigrationColumns(
                        columnsSection.getString("username"),
                        columnsSection.getString("uniqueId"),
                        columnsSection.getString("premiumUniqueId"),
                        columnsSection.getString("passwordHash"),
                        columnsSection.getString("premium"),
                        columnsSection.getString("lastIp"),
                        columnsSection.getString("lastSeen")
                )
        );

        return new PluginConfig(storage, network, premium, bedrock, authorization, visuals, backendBridge, migration);
    }

    Storage storage() {
        return storage;
    }

    Network network() {
        return network;
    }

    Premium premium() {
        return premium;
    }

    Bedrock bedrock() {
        return bedrock;
    }

    Authorization authorization() {
        return authorization;
    }

    Visuals visuals() {
        return visuals;
    }

    BackendBridge backendBridge() {
        return backendBridge;
    }

    Migration migration() {
        return migration;
    }

    private static List<String> normalizeList(List<String> values) {
        return values.stream()
                .filter(value -> value != null && !value.isBlank())
                .map(value -> value.trim().toLowerCase(Locale.ROOT))
                .collect(Collectors.toList());
    }

    private static Set<String> normalizeSet(List<String> values) {
        return new LinkedHashSet<>(normalizeList(values));
    }

    record Storage(String host,
                   int port,
                   String database,
                   String user,
                   String password,
                   List<String> properties,
                   int maximumSize,
                   int minimumIdle,
                   long connectionTimeoutMillis,
                   long maxLifetimeMillis) {
    }

    record Network(String accessToken,
                   Set<String> acceptedHostnames,
                   List<String> limboServers,
                   List<String> mainServers,
                   boolean rememberLastServer,
                   boolean redirectOnKick) {
    }

    record Premium(boolean autoDetectNames,
                   boolean registerPremiumUsers,
                   boolean protectUnregisteredNames,
                   PremiumUuidMode existingPremiumUuidMode) {
    }

    record Bedrock(boolean enabled, List<String> autoLoginPrefixes) {
    }

    record Authorization(HashAlgorithm defaultHashingAlgorithm,
                         String safePasswordPattern,
                         int maximumLoginTriesBeforeDisconnection,
                         int maximumAuthorisationTimeSeconds,
                         int automaticSessionTimeMinutes,
                         Set<String> logoutUserCommands,
                         List<String> loginAliases) {
    }

    record Visuals(long delayTitlesAfterJoinMillis, int reminderIntervalSeconds) {
    }

    record BackendBridge(boolean enabled, String pluginChannel) {
    }

    record Migration(boolean enabled,
                     boolean runOnce,
                     String sourceTable,
                     HashAlgorithm defaultPasswordAlgorithm,
                     FileImport fileImport,
                     MigrationColumns columns) {
    }

    record FileImport(boolean enabled,
                      boolean runOnce,
                      String directory,
                      String fileName) {
    }

    record MigrationColumns(String username,
                            String uniqueId,
                            String premiumUniqueId,
                            String passwordHash,
                            String premium,
                            String lastIp,
                            String lastSeen) {
    }
}
