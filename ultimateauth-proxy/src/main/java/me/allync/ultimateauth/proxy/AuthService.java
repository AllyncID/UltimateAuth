package me.allync.ultimateauth.proxy;

import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.config.ServerInfo;
import net.md_5.bungee.api.connection.PendingConnection;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.event.PreLoginEvent;
import net.md_5.bungee.api.event.PostLoginEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;

import java.lang.reflect.Method;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.SecureRandom;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Consumer;
import java.util.regex.Pattern;

final class AuthService {
    private final UltimateAuthPlugin plugin;
    private final PluginConfig config;
    private final MessageBundle messages;
    private final DatabaseManager database;
    private final PasswordService passwordService;
    private final MojangService mojangService;
    private final FreezeBridge freezeBridge;
    private final Pattern safePasswordPattern;
    private final ConcurrentHashMap<UUID, AuthSession> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, PreparedLogin> pendingPreparations = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();
    private final FloodgateDetector floodgateDetector = new FloodgateDetector();
    private final ConnectionIdentityAccessor connectionIdentityAccessor = new ConnectionIdentityAccessor();
    private final StaleConnectionAccessor staleConnectionAccessor = new StaleConnectionAccessor();

    AuthService(UltimateAuthPlugin plugin,
                PluginConfig config,
                MessageBundle messages,
                DatabaseManager database,
                PasswordService passwordService,
                MojangService mojangService,
                FreezeBridge freezeBridge) {
        this.plugin = plugin;
        this.config = config;
        this.messages = messages;
        this.database = database;
        this.passwordService = passwordService;
        this.mojangService = mojangService;
        this.freezeBridge = freezeBridge;
        this.safePasswordPattern = Pattern.compile(config.authorization().safePasswordPattern());
    }

    void handleLogin(LoginEvent event) {
        PendingConnection connection = event.getConnection();
        String username = connection.getName();
        String usernameLower = DatabaseManager.normalizeName(username);

        event.registerIntent(plugin);
        plugin.getDatabaseExecutor().execute(() -> {
            try {
                PreparedLogin preparedLogin = prepareLogin(
                        username,
                        connection.getUniqueId(),
                        extractIp(connection.getSocketAddress()),
                        connection.isOnlineMode(),
                        isBedrockPlayer(connection)
                );
                pendingPreparations.put(usernameLower, preparedLogin);
            } catch (PremiumAuthenticationRequiredException exception) {
                event.setCancelled(true);
                event.setCancelReason(messages.components(messages.render("errors.premium_name_protected", Map.of("%player%", username))));
            } catch (PremiumVerificationUnavailableException exception) {
                event.setCancelled(true);
                event.setCancelReason(messages.components(messages.render("errors.premium_verification_unavailable", Map.of("%player%", username))));
            } catch (Exception exception) {
                plugin.getLogger().severe("Unable to prepare UltimateAuth login for " + username + ": " + exception.getMessage());
                event.setCancelled(true);
                event.setCancelReason(messages.components(messages.render("errors.account_load_failed", Map.of())));
            } finally {
                event.completeIntent(plugin);
            }
        });
    }

    void handlePreLogin(PreLoginEvent event) {
        PendingConnection connection = event.getConnection();
        String playerName = connection.getName();
        if (playerName == null || playerName.isBlank()) {
            return;
        }

        try {
            Optional<AccountRecord> loaded = database.loadCachedAccount(playerName);
            if (loaded.isPresent()) {
                AccountRecord account = loaded.get();
                if (account.getAccountType() == AccountType.PREMIUM) {
                    connection.setOnlineMode(true);
                }
                applyConnectionIdentity(connection, account);
            }
        } catch (Exception exception) {
            plugin.getLogger().warning("Unable to prepare pre-login UUID for " + playerName + ": " + exception.getMessage());
        }
    }

    void restoreCachedConnectionIdentity(PendingConnection connection) {
        if (connection == null) {
            return;
        }

        String playerName = connection.getName();
        if (playerName == null || playerName.isBlank()) {
            return;
        }

        try {
            Optional<AccountRecord> loaded = database.loadCachedAccount(playerName);
            loaded.ifPresent(account -> applyConnectionIdentity(connection, account));
        } catch (Exception exception) {
            plugin.getLogger().warning("Unable to restore cached login UUID for " + playerName + ": " + exception.getMessage());
        }
    }

    void cleanupStaleDuplicateConnection(PendingConnection connection) {
        if (connection == null) {
            return;
        }

        String playerName = connection.getName();
        if (playerName == null || playerName.isBlank()) {
            return;
        }

        Set<ProxiedPlayer> duplicates = new LinkedHashSet<>();
        ProxiedPlayer byName = findOnlinePlayer(playerName);
        if (byName != null) {
            duplicates.add(byName);
        }

        UUID uniqueId = connection.getUniqueId();
        if (uniqueId != null) {
            ProxiedPlayer byUniqueId = plugin.getProxy().getPlayer(uniqueId);
            if (byUniqueId != null) {
                duplicates.add(byUniqueId);
            }
        }

        UUID offlineId = staleConnectionAccessor.readOfflineId(connection);
        ProxiedPlayer byOfflineId = staleConnectionAccessor.findByOfflineId(plugin.getProxy(), offlineId);
        if (byOfflineId != null) {
            duplicates.add(byOfflineId);
        }

        for (ProxiedPlayer duplicate : duplicates) {
            cleanupStaleDuplicateConnection(duplicate, playerName, uniqueId, offlineId);
        }
    }

    void handleHandshake(PendingConnection connection) {
        String playerName = connection.getName();
        if (playerName == null || playerName.isBlank()) {
            return;
        }

        try {
            Optional<AccountRecord> loaded = database.loadCachedAccount(playerName);
            if (loaded.isPresent()) {
                AccountRecord account = loaded.get();
                applyConnectionIdentity(connection, account);
                if (account.getAccountType() == AccountType.PREMIUM) {
                    connection.setOnlineMode(true);
                }
                return;
            }
            if (!config.premium().autoDetectNames()
                    || !config.premium().protectUnregisteredNames() || isBedrockPlayer(connection)) {
                return;
            }

            PremiumLookupResult lookup = mojangService.lookupProfileResult(playerName);
            if (lookup.found()) {
                connection.setOnlineMode(true);
            }
        } catch (Exception exception) {
            plugin.getLogger().warning("Unable to inspect premium handshake for " + playerName + ": " + exception.getMessage());
        }
    }

    void handlePostLogin(PostLoginEvent event) {
        ProxiedPlayer player = event.getPlayer();
        String usernameLower = DatabaseManager.normalizeName(player.getName());
        PreparedLogin preparedLogin = pendingPreparations.remove(usernameLower);

        if (preparedLogin == null) {
            AccountRecord account = database.loadAccount(player.getName()).orElseGet(() -> {
                AccountRecord created = database.newAccount(player.getName(), player.getUniqueId());
                created.setAccountType(AccountType.CRACKED);
                database.saveAccount(created);
                return created;
            });
            AuthStatus status = account.hasPassword() ? AuthStatus.LOGIN_REQUIRED : AuthStatus.REGISTER_REQUIRED;
            preparedLogin = new PreparedLogin(account, status, null, null);
        }

        applyPlayerIdentity(player, preparedLogin.account());
        AuthSession session = sessions.computeIfAbsent(player.getUniqueId(), uniqueId -> new AuthSession(uniqueId, player.getName()));
        session.cancelTasks();
        session.setLastKnownName(player.getName());
        session.setAccount(preparedLogin.account());
        session.setStatus(preparedLogin.status());
        session.setJoinMessageKey(preparedLogin.joinMessageKey());
        session.setJoinTitleKey(preparedLogin.joinTitleKey());
        session.resetFailedLoginAttempts();
        session.setAuthDeadlineAt(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(config.authorization().maximumAuthorisationTimeSeconds()));

        ServerInfo target = preparedLogin.status() == AuthStatus.AUTHORIZED
                ? resolveAuthorizedServer(preparedLogin.account())
                : resolveLimboServer();
        if (target != null) {
            event.setTarget(target);
        }
    }

    boolean isAuthenticated(ProxiedPlayer player) {
        AuthSession session = sessions.get(player.getUniqueId());
        return session != null && session.isAuthorized();
    }

    boolean shouldBlock(ProxiedPlayer player) {
        AuthSession session = sessions.get(player.getUniqueId());
        return session == null || !session.isAuthorized();
    }

    boolean isAllowedUnauthenticatedCommand(String command) {
        if ("premium".equals(command) || "cracked".equals(command)) {
            return false;
        }
        return config.authorization().logoutUserCommands().contains(command);
    }

    ServerInfo resolveAuthorizedServerFor(ProxiedPlayer player) {
        AuthSession session = sessions.get(player.getUniqueId());
        if (session == null || session.getAccount() == null) {
            return resolveServer(config.network().mainServers());
        }
        return resolveAuthorizedServer(session.getAccount());
    }

    void handleServerSwitch(ProxiedPlayer player) {
        AuthSession session = sessions.get(player.getUniqueId());
        if (session == null) {
            return;
        }

        if (session.isAuthorized()) {
            session.cancelTasks();
            freezeBridge.pushState(player, false);
            flushJoinAnnouncements(player, session);
            return;
        }

        ServerInfo limbo = resolveLimboServer();
        if (limbo == null) {
            player.disconnect(messages.components(messages.render("errors.limbo_missing", Map.of())));
            return;
        }

        if (player.getServer() == null || !player.getServer().getInfo().getName().equalsIgnoreCase(limbo.getName())) {
            player.connect(limbo);
            return;
        }

        freezeBridge.pushState(player, true);
        beginChallenge(player, session);
    }

    void handleDisconnect(ProxiedPlayer player) {
        pendingPreparations.remove(DatabaseManager.normalizeName(player.getName()));
        AuthSession session = sessions.remove(player.getUniqueId());
        if (session == null) {
            return;
        }

        session.cancelTasks();
        AccountRecord account = session.getAccount();
        if (account != null && session.isAuthorized() && player.getServer() != null) {
            account.setLastServer(player.getServer().getInfo().getName());
            account.setUpdatedAt(System.currentTimeMillis());
            plugin.getDatabaseExecutor().execute(() -> database.saveAccount(account));
        }
    }

    void attemptRegister(ProxiedPlayer player, String password) {
        AuthSession session = sessions.get(player.getUniqueId());
        if (session == null) {
            messages.send(player, "errors.account_load_failed");
            return;
        }

        AccountRecord account = session.getAccount();
        if (account == null) {
            account = database.newAccount(player.getName(), player.getUniqueId());
            session.setAccount(account);
        }
        if (account.hasPassword()) {
            messages.send(player, "errors.already_registered");
            return;
        }
        if (!safePasswordPattern.matcher(password).matches()) {
            messages.send(player, "errors.password_invalid", Map.of("%pattern%", config.authorization().safePasswordPattern()));
            return;
        }

        account.setLastName(player.getName());
        if (account.getPlayerUuid() == null) {
            account.setPlayerUuid(player.getUniqueId());
        }
        account.setAccountType(AccountType.CRACKED);
        account.setPasswordAlgorithm(config.authorization().defaultHashingAlgorithm());
        account.setPasswordHash(passwordService.hash(password, config.authorization().defaultHashingAlgorithm()));
        if (account.getRegisteredAt() == 0L) {
            account.setRegisteredAt(System.currentTimeMillis());
        }
        account.setUpdatedAt(System.currentTimeMillis());

        AccountRecord finalAccount = account;
        plugin.getDatabaseExecutor().execute(() -> {
            database.saveAccount(finalAccount);
            if (session.isAuthorized()) {
                messages.send(player, "auth.register_success");
            } else {
                authorize(player, session, finalAccount, "auth.register_success", "authorized");
            }
        });
    }

    void attemptLogin(ProxiedPlayer player, String password) {
        if (player != null) {
            attemptLoginSecure(player, password);
            return;
        }
        AuthSession session = sessions.get(player.getUniqueId());
        if (session == null || session.getAccount() == null) {
            messages.send(player, "errors.account_load_failed");
            return;
        }

        AccountRecord account = session.getAccount();
        if (!account.hasPassword()) {
            messages.send(player, "errors.not_registered");
            return;
        }
        if (session.isAuthorized()) {
            messages.send(player, "errors.already_authorized");
            return;
        }
        if (!passwordService.matches(password, account)) {
            int attempts = session.incrementFailedLoginAttempts();
            int maxTries = config.authorization().maximumLoginTriesBeforeDisconnection();
            int remaining = maxTries <= 0 ? Integer.MAX_VALUE : Math.max(0, maxTries - attempts);
            messages.send(player, "errors.password_wrong", Map.of("%tries%", remaining == Integer.MAX_VALUE ? "∞" : String.valueOf(remaining)));
            if (maxTries > 0 && attempts >= maxTries) {
                player.disconnect(messages.components(messages.render("auth.timeout", Map.of())));
            }
            return;
        }

        authorize(player, session, account, "auth.login_success", "authorized");
    }

    void changePassword(ProxiedPlayer player, String oldPassword, String newPassword) {
        AuthSession session = sessions.get(player.getUniqueId());
        if (session == null || session.getAccount() == null) {
            messages.send(player, "errors.account_load_failed");
            return;
        }
        if (!session.isAuthorized()) {
            messages.send(player, "errors.login_required");
            return;
        }

        AccountRecord account = session.getAccount();
        if (!account.hasPassword()) {
            messages.send(player, "errors.not_registered");
            return;
        }
        if (!passwordService.matches(oldPassword, account)) {
            messages.send(player, "errors.change_password_old_wrong");
            return;
        }
        if (!safePasswordPattern.matcher(newPassword).matches()) {
            messages.send(player, "errors.password_invalid", Map.of("%pattern%", config.authorization().safePasswordPattern()));
            return;
        }

        account.setPasswordAlgorithm(config.authorization().defaultHashingAlgorithm());
        account.setPasswordHash(passwordService.hash(newPassword, config.authorization().defaultHashingAlgorithm()));
        account.setUpdatedAt(System.currentTimeMillis());

        plugin.getDatabaseExecutor().execute(() -> {
            database.saveAccount(account);
            messages.send(player, "auth.change_password_success");
            messages.sendTitle(player, "change_password_disconnect", Map.of("%player%", player.getName()));
            plugin.getProxy().getScheduler().schedule(plugin, () -> {
                if (player.isConnected()) {
                    player.disconnect(messages.components(messages.render("auth.change_password_disconnect_screen", Map.of("%player%", player.getName()))));
                }
            }, 2, TimeUnit.SECONDS);
        });
    }

    void switchToPremium(ProxiedPlayer player) {
        if (player != null) {
            switchToPremiumSecure(player);
            return;
        }
        AuthSession session = sessions.computeIfAbsent(player.getUniqueId(), uniqueId -> new AuthSession(uniqueId, player.getName()));
        AccountRecord currentAccount = Optional.ofNullable(session.getAccount())
                .or(() -> database.loadAccount(player.getName()))
                .orElse(null);
        if (currentAccount != null && currentAccount.getAccountType() == AccountType.PREMIUM) {
            messages.send(player, "auth.already_premium");
            messages.sendTitle(player, "already_premium", Map.of("%player%", player.getName()));
            return;
        }

        plugin.getDatabaseExecutor().execute(() -> {
            Optional<PremiumProfile> profile = mojangService.lookupProfile(player.getName());
            if (profile.isEmpty()) {
                messages.send(player, "errors.premium_name_required");
                messages.sendTitle(player, "premium_warning", Map.of("%player%", player.getName()));
                return;
            }

            AccountRecord account = Optional.ofNullable(session.getAccount())
                    .or(() -> database.loadAccount(player.getName()))
                    .orElseGet(() -> database.newAccount(player.getName(), player.getUniqueId()));
            account.setLastName(player.getName());
            if (account.getPlayerUuid() == null) {
                account.setPlayerUuid(player.getUniqueId());
            }
            account.setPremiumUuid(profile.get().uuid());
            account.setAccountType(AccountType.PREMIUM);
            account.setUpdatedAt(System.currentTimeMillis());
            database.saveAccount(account);

            if (session.isAuthorized()) {
                session.setAccount(account);
                session.setStatus(AuthStatus.AUTHORIZED);
                messages.send(player, "auth.switched_premium");
                messages.sendTitle(player, "premium", Map.of());
                connectToAuthorizedServer(player, account);
                freezeBridge.pushState(player, false);
            } else {
                authorize(player, session, account, "auth.switched_premium", "premium");
            }
        });
    }

    void switchToCracked(ProxiedPlayer player) {
        if (player != null) {
            switchToCrackedSecure(player);
            return;
        }
        AuthSession session = sessions.computeIfAbsent(player.getUniqueId(), uniqueId -> new AuthSession(uniqueId, player.getName()));
        AccountRecord account = Optional.ofNullable(session.getAccount())
                .or(() -> database.loadAccount(player.getName()))
                .orElseGet(() -> database.newAccount(player.getName(), player.getUniqueId()));
        if (account.getAccountType() == AccountType.CRACKED) {
            messages.send(player, "auth.already_cracked");
            messages.sendTitle(player, "already_cracked", Map.of("%player%", player.getName()));
            return;
        }
        boolean wasPremium = account.getAccountType() == AccountType.PREMIUM;

        account.setLastName(player.getName());
        if (account.getPlayerUuid() == null) {
            account.setPlayerUuid(player.getUniqueId());
        }
        account.setAccountType(AccountType.CRACKED);
        account.setPremiumUuid(null);
        account.setSessionIp(null);
        account.setSessionExpiresAt(0L);
        account.setUpdatedAt(System.currentTimeMillis());

        plugin.getDatabaseExecutor().execute(() -> {
            database.saveAccount(account);
            session.setAccount(account);

            if (wasPremium) {
                session.cancelTasks();
                session.setStatus(account.hasPassword() ? AuthStatus.LOGIN_REQUIRED : AuthStatus.REGISTER_REQUIRED);
                freezeBridge.pushState(player, true);
                messages.send(player, "auth.switched_cracked_disconnect");
                messages.sendTitle(player, "cracked_disconnect", Map.of("%player%", player.getName()));
                plugin.getProxy().getScheduler().schedule(plugin, () -> {
                    if (player.isConnected()) {
                        player.disconnect(messages.components(messages.render("auth.cracked_disconnect_screen", Map.of("%player%", player.getName()))));
                    }
                }, 2, TimeUnit.SECONDS);
                return;
            }

            messages.send(player, "auth.switched_cracked");

            if (session.isAuthorized()) {
                if (!account.hasPassword()) {
                    messages.send(player, "auth.cracked_needs_register");
                }
                return;
            }

            session.setStatus(account.hasPassword() ? AuthStatus.LOGIN_REQUIRED : AuthStatus.REGISTER_REQUIRED);
            session.setAuthDeadlineAt(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(config.authorization().maximumAuthorisationTimeSeconds()));
            if (!account.hasPassword()) {
                messages.send(player, "auth.cracked_needs_register");
            }
            connectToLimbo(player);
        });
    }

    void forcePremium(CommandSender sender, String playerName) {
        forceAccountChange(sender, playerName, account -> {
            account.setAccountType(AccountType.PREMIUM);
            account.setUpdatedAt(System.currentTimeMillis());
        }, "admin.forcepremium");
    }

    void forceCracked(CommandSender sender, String playerName) {
        forceAccountChange(sender, playerName, account -> {
            account.setAccountType(AccountType.CRACKED);
            account.setPremiumUuid(null);
            account.setSessionIp(null);
            account.setSessionExpiresAt(0L);
            account.setUpdatedAt(System.currentTimeMillis());
        }, "admin.forcecracked");
    }

    void forceUnregister(CommandSender sender, String playerName) {
        plugin.getDatabaseExecutor().execute(() -> {
            Optional<AccountRecord> loaded = database.loadAccount(playerName);
            if (loaded.isEmpty()) {
                messages.send(sender, "errors.player_not_found");
                return;
            }

            AccountRecord account = loaded.get();
            account.setAccountType(AccountType.CRACKED);
            account.setPasswordHash(null);
            account.setSessionIp(null);
            account.setSessionExpiresAt(0L);
            account.setUpdatedAt(System.currentTimeMillis());
            database.saveAccount(account);
            messages.send(sender, "admin.forceunregister", Map.of("%player%", playerName));
            refreshOnlineState(playerName);
        });
    }

    void forceRegister(CommandSender sender, String playerName, String password) {
        String actualPassword = password == null || password.isBlank() ? randomPassword() : password;
        plugin.getDatabaseExecutor().execute(() -> {
            AccountRecord account = database.loadAccount(playerName).orElseGet(() -> database.newAccount(playerName, null));
            account.setLastName(playerName);
            account.setAccountType(AccountType.CRACKED);
            account.setPasswordAlgorithm(config.authorization().defaultHashingAlgorithm());
            account.setPasswordHash(passwordService.hash(actualPassword, config.authorization().defaultHashingAlgorithm()));
            if (account.getRegisteredAt() == 0L) {
                account.setRegisteredAt(System.currentTimeMillis());
            }
            account.setSessionIp(null);
            account.setSessionExpiresAt(0L);
            account.setUpdatedAt(System.currentTimeMillis());
            database.saveAccount(account);
            messages.send(sender, "admin.forceregister", Map.of("%player%", playerName, "%password%", actualPassword));
            refreshOnlineState(playerName);
        });
    }

    ServerInfo resolveLimboServer() {
        return resolveServer(config.network().limboServers());
    }

    ServerInfo resolveAuthorizedServer(AccountRecord account) {
        if (config.network().rememberLastServer() && account.getLastServer() != null) {
            ServerInfo lastServer = plugin.getProxy().getServerInfo(account.getLastServer());
            if (lastServer != null) {
                return lastServer;
            }
        }
        return resolveServer(config.network().mainServers());
    }

    private PreparedLogin prepareLogin(String playerName,
                                       UUID playerUuid,
                                       String ipAddress,
                                       boolean onlineMode,
                                       boolean bedrockPlayer) {
        long now = System.currentTimeMillis();
        Optional<AccountRecord> loaded = database.loadAccount(playerName);
        AccountRecord account = loaded.orElse(null);

        if (account == null) {
            if (bedrockPlayer) {
                account = database.newAccount(playerName, resolvePlayerUuid(null, playerUuid, true));
                account.setAccountType(AccountType.BEDROCK);
                account.setLastIp(ipAddress);
                account.setLastLoginAt(now);
                account.setUpdatedAt(now);
                database.saveAccount(account);
                return new PreparedLogin(account, AuthStatus.AUTHORIZED, "auth.auto_login_bedrock", "bedrock");
            }

            if (onlineMode) {
                account = database.newAccount(playerName, playerUuid);
                account.setPremiumUuid(playerUuid);
                account.setAccountType(AccountType.PREMIUM);
                account.setLastIp(ipAddress);
                account.setLastLoginAt(now);
                account.setUpdatedAt(now);
                database.saveAccount(account);
                return new PreparedLogin(account, AuthStatus.AUTHORIZED, "auth.auto_login_premium", "premium");
            }

            if (config.premium().autoDetectNames() && config.premium().protectUnregisteredNames()) {
                PremiumLookupResult premiumLookup = mojangService.lookupProfileResult(playerName);
                if (premiumLookup.status() == PremiumLookupStatus.ERROR) {
                    throw new PremiumVerificationUnavailableException();
                }
                if (premiumLookup.found()) {
                    throw new PremiumAuthenticationRequiredException();
                }
            }

            account = database.newAccount(playerName, playerUuid);
            account.setAccountType(AccountType.CRACKED);
            database.saveAccount(account);
            return new PreparedLogin(account, AuthStatus.REGISTER_REQUIRED, null, null);
        }

        account.setLastName(playerName);
        syncPlayerUuid(account, playerUuid, bedrockPlayer);

        if (bedrockPlayer && account.getAccountType() != AccountType.BEDROCK) {
            account.setAccountType(AccountType.BEDROCK);
            account.setSessionIp(null);
            account.setSessionExpiresAt(0L);
            account.setUpdatedAt(now);
            database.saveAccount(account);
        }

        if (account.getAccountType() == AccountType.PREMIUM) {
            if (!onlineMode) {
                plugin.getLogger().warning("Rejected premium login for " + playerName
                        + " because the connection reached LoginEvent without online-mode enabled."
                        + " playerUuid=" + account.getPlayerUuid()
                        + ", premiumUuid=" + account.getPremiumUuid());
                throw new PremiumAuthenticationRequiredException();
            }
            account.setLastIp(ipAddress);
            account.setLastLoginAt(now);
            account.setUpdatedAt(now);
            database.saveAccount(account);
            return new PreparedLogin(account, AuthStatus.AUTHORIZED, "auth.auto_login_premium", "premium");
        }

        if (account.getAccountType() == AccountType.BEDROCK) {
            account.setLastIp(ipAddress);
            account.setLastLoginAt(now);
            account.setUpdatedAt(now);
            database.saveAccount(account);
            return new PreparedLogin(account, AuthStatus.AUTHORIZED, "auth.auto_login_bedrock", "bedrock");
        }

        if (account.hasValidSession(ipAddress, now)) {
            startSession(account, ipAddress);
            database.saveAccount(account);
            return new PreparedLogin(account, AuthStatus.AUTHORIZED, "auth.auto_login_session", "authorized");
        }

        if (account.getSessionExpiresAt() > 0L && account.getSessionExpiresAt() <= now) {
            account.setSessionIp(null);
            account.setSessionExpiresAt(0L);
            account.setUpdatedAt(now);
            database.saveAccount(account);
        }

        return new PreparedLogin(account, account.hasPassword() ? AuthStatus.LOGIN_REQUIRED : AuthStatus.REGISTER_REQUIRED, null, null);
    }

    private PreparedLogin prepareLogin(String playerName, UUID playerUuid, String ipAddress) {
        long now = System.currentTimeMillis();
        boolean bedrockPlayer = isBedrockPlayer(playerName);
        Optional<AccountRecord> loaded = database.loadAccount(playerName);
        AccountRecord account = loaded.orElse(null);

        if (account == null) {
            if (bedrockPlayer) {
                account = database.newAccount(playerName, resolvePlayerUuid(null, playerUuid, true));
                account.setAccountType(AccountType.BEDROCK);
                account.setLastIp(ipAddress);
                account.setLastLoginAt(now);
                account.setUpdatedAt(now);
                database.saveAccount(account);
                return new PreparedLogin(account, AuthStatus.AUTHORIZED, "auth.auto_login_bedrock", "bedrock");
            }

            Optional<PremiumProfile> premiumProfile = config.premium().autoDetectNames()
                    ? mojangService.lookupProfile(playerName)
                    : Optional.empty();

            if (premiumProfile.isPresent() && config.premium().registerPremiumUsers()) {
                account = database.newAccount(playerName, playerUuid);
                account.setPremiumUuid(premiumProfile.get().uuid());
                account.setAccountType(AccountType.PREMIUM);
                account.setLastIp(ipAddress);
                account.setLastLoginAt(now);
                account.setUpdatedAt(now);
                database.saveAccount(account);
                return new PreparedLogin(account, AuthStatus.AUTHORIZED, "auth.auto_login_premium", "premium");
            }

            account = database.newAccount(playerName, playerUuid);
            account.setAccountType(AccountType.CRACKED);
            database.saveAccount(account);
            return new PreparedLogin(account, AuthStatus.REGISTER_REQUIRED, null, null);
        }

        account.setLastName(playerName);
        syncPlayerUuid(account, playerUuid, bedrockPlayer);

        if (bedrockPlayer && account.getAccountType() != AccountType.BEDROCK) {
            account.setAccountType(AccountType.BEDROCK);
            account.setSessionIp(null);
            account.setSessionExpiresAt(0L);
            account.setUpdatedAt(now);
            database.saveAccount(account);
        }

        if (account.getAccountType() == AccountType.PREMIUM) {
            account.setLastIp(ipAddress);
            account.setLastLoginAt(now);
            account.setUpdatedAt(now);
            database.saveAccount(account);
            return new PreparedLogin(account, AuthStatus.AUTHORIZED, "auth.auto_login_premium", "premium");
        }

        if (account.getAccountType() == AccountType.BEDROCK) {
            account.setLastIp(ipAddress);
            account.setLastLoginAt(now);
            account.setUpdatedAt(now);
            database.saveAccount(account);
            return new PreparedLogin(account, AuthStatus.AUTHORIZED, "auth.auto_login_bedrock", "bedrock");
        }

        if (account.hasValidSession(ipAddress, now)) {
            startSession(account, ipAddress);
            database.saveAccount(account);
            return new PreparedLogin(account, AuthStatus.AUTHORIZED, "auth.auto_login_session", "authorized");
        }

        if (account.getSessionExpiresAt() > 0L && account.getSessionExpiresAt() <= now) {
            account.setSessionIp(null);
            account.setSessionExpiresAt(0L);
            account.setUpdatedAt(now);
            database.saveAccount(account);
        }

        return new PreparedLogin(account, account.hasPassword() ? AuthStatus.LOGIN_REQUIRED : AuthStatus.REGISTER_REQUIRED, null, null);
    }

    private void authorize(ProxiedPlayer player,
                           AuthSession session,
                           AccountRecord account,
                           String messageKey,
                           String titleKey) {
        startSession(account, extractIp(player.getSocketAddress()));
        account.setLastName(player.getName());
        if (account.getPlayerUuid() == null) {
            account.setPlayerUuid(player.getUniqueId());
        }
        account.setLastIp(extractIp(player.getSocketAddress()));
        account.setLastLoginAt(System.currentTimeMillis());
        account.setUpdatedAt(System.currentTimeMillis());
        database.saveAccount(account);

        session.setAccount(account);
        session.setStatus(AuthStatus.AUTHORIZED);
        session.setJoinMessageKey(null);
        session.setJoinTitleKey(null);
        session.resetFailedLoginAttempts();
        session.cancelTasks();

        freezeBridge.pushState(player, false);
        messages.send(player, messageKey);
        messages.sendTitle(player, titleKey, Map.of());
        connectToAuthorizedServer(player, account);
    }

    private void beginChallenge(ProxiedPlayer player, AuthSession session) {
        if (session.getReminderTask() != null || session.getTimeoutTask() != null) {
            return;
        }

        String titleKey = session.getStatus() == AuthStatus.REGISTER_REQUIRED ? "register" : "login";
        MessageBundle.TitleSettings titleSettings = messages.titleSettings(
                titleKey,
                Math.max(0L, config.visuals().delayTitlesAfterJoinMillis()),
                Math.max(1, config.visuals().reminderIntervalSeconds()),
                true
        );
        long delayMillis = Math.max(0L, titleSettings.delayMillis());
        long periodMillis = Math.max(1000L, TimeUnit.SECONDS.toMillis(Math.max(1, titleSettings.repeatIntervalSeconds())));
        AtomicBoolean firstTitle = new AtomicBoolean(true);

        session.setReminderTask(plugin.getProxy().getScheduler().schedule(plugin, () -> {
            if (!player.isConnected() || session.isAuthorized()) {
                session.cancelTasks();
                return;
            }
            long secondsLeft = Math.max(1L, TimeUnit.MILLISECONDS.toSeconds(Math.max(0L, session.getAuthDeadlineAt() - System.currentTimeMillis())));
            String messageKey = session.getStatus() == AuthStatus.REGISTER_REQUIRED ? "auth.reminder_register" : "auth.reminder_login";
            Map<String, String> placeholders = Map.of("%time%", formatDuration(secondsLeft));
            messages.send(player, messageKey, placeholders);
            if (titleSettings.repeat() || firstTitle.getAndSet(false)) {
                messages.sendTitle(player, titleKey, placeholders);
            }
            freezeBridge.pushState(player, true);
        }, delayMillis, periodMillis, TimeUnit.MILLISECONDS));

        session.setTimeoutTask(plugin.getProxy().getScheduler().schedule(plugin, () -> {
            if (!player.isConnected() || session.isAuthorized()) {
                return;
            }
            messages.sendTitle(player, "timeout", Map.of());
            player.disconnect(messages.components(messages.render("auth.timeout", Map.of())));
        }, config.authorization().maximumAuthorisationTimeSeconds(), TimeUnit.SECONDS));
    }

    private void flushJoinAnnouncements(ProxiedPlayer player, AuthSession session) {
        String messageKey = session.getJoinMessageKey();
        String titleKey = session.getJoinTitleKey();
        if (messageKey != null) {
            messages.send(player, messageKey, Map.of("%player%", player.getName()));
            session.setJoinMessageKey(null);
        }
        if (titleKey != null) {
            messages.sendTitle(player, titleKey, Map.of("%player%", player.getName()));
            session.setJoinTitleKey(null);
        }
    }

    private void forceAccountChange(CommandSender sender, String playerName, Consumer<AccountRecord> mutator, String messageKey) {
        plugin.getDatabaseExecutor().execute(() -> {
            AccountRecord account = database.loadAccount(playerName).orElseGet(() -> database.newAccount(playerName, null));
            account.setLastName(playerName);
            mutator.accept(account);
            database.saveAccount(account);
            messages.send(sender, messageKey, Map.of("%player%", playerName));
            refreshOnlineState(playerName);
        });
    }

    private void startSession(AccountRecord account, String ipAddress) {
        long now = System.currentTimeMillis();
        account.setSessionIp(ipAddress);
        account.setSessionExpiresAt(now + TimeUnit.MINUTES.toMillis(config.authorization().automaticSessionTimeMinutes()));
        account.setUpdatedAt(now);
    }

    private void refreshOnlineState(String playerName) {
        ProxiedPlayer online = findOnlinePlayer(playerName);
        if (online == null) {
            return;
        }

        plugin.getDatabaseExecutor().execute(() -> {
            Optional<AccountRecord> loaded = database.loadAccount(playerName);
            if (loaded.isEmpty()) {
                return;
            }

            AccountRecord account = loaded.get();
            AuthSession session = sessions.computeIfAbsent(online.getUniqueId(), uniqueId -> new AuthSession(uniqueId, online.getName()));
            session.cancelTasks();
            session.setAccount(account);
            session.setLastKnownName(online.getName());
            session.setAuthDeadlineAt(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(config.authorization().maximumAuthorisationTimeSeconds()));
            session.resetFailedLoginAttempts();

            if (account.getAccountType() == AccountType.PREMIUM) {
                session.setStatus(AuthStatus.AUTHORIZED);
                freezeBridge.pushState(online, false);
                messages.send(online, "auth.auto_login_premium", Map.of("%player%", online.getName()));
                messages.sendTitle(online, "premium", Map.of("%player%", online.getName()));
                connectToAuthorizedServer(online, account);
                return;
            }

            if (account.getAccountType() == AccountType.BEDROCK) {
                session.setStatus(AuthStatus.AUTHORIZED);
                freezeBridge.pushState(online, false);
                messages.send(online, "auth.auto_login_bedrock", Map.of("%player%", online.getName()));
                messages.sendTitle(online, "bedrock", Map.of("%player%", online.getName()));
                connectToAuthorizedServer(online, account);
                return;
            }

            session.setStatus(account.hasPassword() ? AuthStatus.LOGIN_REQUIRED : AuthStatus.REGISTER_REQUIRED);
            connectToLimbo(online);
            if (!account.hasPassword()) {
                messages.send(online, "auth.cracked_needs_register");
            }
        });
    }

    private void connectToAuthorizedServer(ProxiedPlayer player, AccountRecord account) {
        ServerInfo target = resolveAuthorizedServer(account);
        if (target == null) {
            player.disconnect(messages.components(messages.render("errors.main_missing", Map.of())));
            return;
        }
        if (player.getServer() != null && player.getServer().getInfo().getName().equalsIgnoreCase(target.getName())) {
            return;
        }
        connectPlayer(player, target, "authorized");
    }

    private void connectToLimbo(ProxiedPlayer player) {
        ServerInfo limbo = resolveLimboServer();
        if (limbo == null) {
            player.disconnect(messages.components(messages.render("errors.limbo_missing", Map.of())));
            return;
        }
        if (player.getServer() != null && player.getServer().getInfo().getName().equalsIgnoreCase(limbo.getName())) {
            AuthSession session = sessions.get(player.getUniqueId());
            if (session != null) {
                beginChallenge(player, session);
            }
            return;
        }
        connectPlayer(player, limbo, "limbo");
    }

    private void connectPlayer(ProxiedPlayer player, ServerInfo target, String purpose) {
        player.connect(target, (result, error) -> {
            if (error != null) {
                plugin.getLogger().warning("Unable to connect " + player.getName() + " to " + target.getName()
                        + " (" + purpose + "): " + error.getMessage());
                return;
            }
            if (!Boolean.TRUE.equals(result)) {
                plugin.getLogger().warning("Connection request for " + player.getName() + " to " + target.getName()
                        + " (" + purpose + ") was rejected without an exception.");
            }
        }, ServerConnectEvent.Reason.PLUGIN);
    }

    private ServerInfo resolveServer(List<String> configuredNames) {
        for (String configuredName : configuredNames) {
            ServerInfo info = plugin.getProxy().getServerInfo(configuredName);
            if (info != null) {
                return info;
            }
        }
        return null;
    }

    private ProxiedPlayer findOnlinePlayer(String playerName) {
        ProxiedPlayer exact = plugin.getProxy().getPlayer(playerName);
        if (exact != null) {
            return exact;
        }
        for (ProxiedPlayer player : plugin.getProxy().getPlayers()) {
            if (player.getName().equalsIgnoreCase(playerName)) {
                return player;
            }
        }
        return null;
    }

    private void cleanupStaleDuplicateConnection(ProxiedPlayer duplicate,
                                                 String incomingName,
                                                 UUID incomingUniqueId,
                                                 UUID incomingOfflineId) {
        if (duplicate == null || duplicate.isConnected()) {
            return;
        }

        boolean matchingName = duplicate.getName().equalsIgnoreCase(incomingName);
        boolean matchingUniqueId = incomingUniqueId != null && incomingUniqueId.equals(duplicate.getUniqueId());
        UUID duplicateOfflineId = staleConnectionAccessor.readOfflineId(duplicate.getPendingConnection());
        boolean matchingOfflineId = incomingOfflineId != null && incomingOfflineId.equals(duplicateOfflineId);
        if (!matchingName && !matchingUniqueId && !matchingOfflineId) {
            return;
        }

        handleDisconnect(duplicate);
        if (staleConnectionAccessor.remove(plugin.getProxy(), duplicate)) {
            plugin.getLogger().info("Cleared stale proxy connection for " + duplicate.getName() + " to allow a reconnect.");
        }
    }

    private String extractIp(SocketAddress socketAddress) {
        if (socketAddress instanceof InetSocketAddress inetSocketAddress && inetSocketAddress.getAddress() != null) {
            return inetSocketAddress.getAddress().getHostAddress();
        }
        return socketAddress == null ? "unknown" : socketAddress.toString();
    }

    private String randomPassword() {
        String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        StringBuilder builder = new StringBuilder(10);
        for (int index = 0; index < 10; index++) {
            builder.append(alphabet.charAt(secureRandom.nextInt(alphabet.length())));
        }
        return builder.toString();
    }

    private void attemptLoginSecure(ProxiedPlayer player, String password) {
        AuthSession session = sessions.get(player.getUniqueId());
        if (session == null || session.getAccount() == null) {
            messages.send(player, "errors.account_load_failed");
            return;
        }

        AccountRecord account = session.getAccount();
        if (!account.hasPassword()) {
            messages.send(player, "errors.not_registered");
            return;
        }
        if (session.isAuthorized()) {
            messages.send(player, "errors.already_authorized");
            return;
        }

        int maxTries = config.authorization().maximumLoginTriesBeforeDisconnection();
        if (!passwordService.matches(password, account)) {
            if (maxTries <= 0) {
                messages.send(player, "errors.password_wrong", Map.of("%tries%", "∞"));
                return;
            }

            int attempts = session.incrementFailedLoginAttempts();
            int remaining = Math.max(0, maxTries - attempts);
            if (attempts >= maxTries) {
                Map<String, String> placeholders = Map.of("%time%", "until you reconnect");
                messages.send(player, "errors.login_locked", placeholders);
                player.disconnect(messages.components(messages.render("errors.login_locked", placeholders)));
                return;
            }

            messages.send(player, "errors.password_wrong", Map.of("%tries%", String.valueOf(remaining)));
            return;
        }

        authorize(player, session, account, "auth.login_success", "authorized");
    }

    private void switchToPremiumSecure(ProxiedPlayer player) {
        AuthSession session = sessions.get(player.getUniqueId());
        if (!ensureAuthorizedForAccountModeChange(player, session)) {
            return;
        }

        AccountRecord currentAccount = session.getAccount();
        if (currentAccount.getAccountType() == AccountType.PREMIUM) {
            messages.send(player, "auth.already_premium");
            messages.sendTitle(player, "already_premium", Map.of("%player%", player.getName()));
            return;
        }

        plugin.getDatabaseExecutor().execute(() -> {
            PremiumLookupResult lookup = mojangService.lookupProfileResult(player.getName());
            if (lookup.status() == PremiumLookupStatus.ERROR) {
                messages.send(player, "errors.premium_verification_unavailable");
                return;
            }
            if (!lookup.found()) {
                messages.send(player, "errors.premium_name_required");
                messages.sendTitle(player, "premium_warning", Map.of("%player%", player.getName()));
                return;
            }

            AccountRecord account = session.getAccount();
            account.setLastName(player.getName());
            if (account.getPlayerUuid() == null) {
                account.setPlayerUuid(player.getUniqueId());
            }
            account.setPremiumUuid(lookup.profile().uuid());
            account.setAccountType(AccountType.PREMIUM);
            account.setSessionIp(null);
            account.setSessionExpiresAt(0L);
            account.setUpdatedAt(System.currentTimeMillis());
            database.saveAccount(account);

            session.cancelTasks();
            session.setAccount(account);
            session.setStatus(AuthStatus.LOGIN_REQUIRED);
            freezeBridge.pushState(player, true);
            messages.send(player, "auth.switched_premium_disconnect");
            messages.sendTitle(player, "premium_reconnect", Map.of("%player%", player.getName()));
            plugin.getProxy().getScheduler().schedule(plugin, () -> {
                if (player.isConnected()) {
                    player.disconnect(messages.components(messages.render("auth.premium_disconnect_screen", Map.of("%player%", player.getName()))));
                }
            }, 2, TimeUnit.SECONDS);
        });
    }

    private void switchToCrackedSecure(ProxiedPlayer player) {
        AuthSession session = sessions.get(player.getUniqueId());
        if (!ensureAuthorizedForAccountModeChange(player, session)) {
            return;
        }

        AccountRecord account = session.getAccount();
        if (account.getAccountType() == AccountType.CRACKED) {
            messages.send(player, "auth.already_cracked");
            messages.sendTitle(player, "already_cracked", Map.of("%player%", player.getName()));
            return;
        }
        boolean wasPremium = account.getAccountType() == AccountType.PREMIUM;

        account.setLastName(player.getName());
        if (account.getPlayerUuid() == null) {
            account.setPlayerUuid(player.getUniqueId());
        }
        account.setAccountType(AccountType.CRACKED);
        account.setPremiumUuid(null);
        account.setSessionIp(null);
        account.setSessionExpiresAt(0L);
        account.setUpdatedAt(System.currentTimeMillis());

        plugin.getDatabaseExecutor().execute(() -> {
            database.saveAccount(account);
            session.setAccount(account);

            if (wasPremium) {
                session.cancelTasks();
                session.setStatus(account.hasPassword() ? AuthStatus.LOGIN_REQUIRED : AuthStatus.REGISTER_REQUIRED);
                freezeBridge.pushState(player, true);
                messages.send(player, "auth.switched_cracked_disconnect");
                messages.sendTitle(player, "cracked_disconnect", Map.of("%player%", player.getName()));
                plugin.getProxy().getScheduler().schedule(plugin, () -> {
                    if (player.isConnected()) {
                        player.disconnect(messages.components(messages.render("auth.cracked_disconnect_screen", Map.of("%player%", player.getName()))));
                    }
                }, 2, TimeUnit.SECONDS);
                return;
            }

            messages.send(player, "auth.switched_cracked");
            if (!account.hasPassword()) {
                messages.send(player, "auth.cracked_needs_register");
            }
        });
    }

    private boolean ensureAuthorizedForAccountModeChange(ProxiedPlayer player, AuthSession session) {
        if (session == null || session.getAccount() == null) {
            messages.send(player, "errors.account_load_failed");
            return false;
        }
        if (session.isAuthorized()) {
            return true;
        }

        if (session.getStatus() == AuthStatus.REGISTER_REQUIRED) {
            messages.send(player, "errors.register_required");
        } else if (session.getStatus() == AuthStatus.LOGIN_REQUIRED) {
            messages.send(player, "errors.login_required");
        } else {
            messages.send(player, "errors.account_mode_change_requires_auth");
        }
        return false;
    }

    private UUID resolvePlayerUuid(AccountRecord account, UUID liveUniqueId, boolean detectedBedrock) {
        if (shouldUseBedrockUuid(account, detectedBedrock)) {
            UUID legacyBedrockUuid = resolveLegacyBedrockUniqueId(account == null ? null : account.getPlayerUuid(), liveUniqueId);
            if (legacyBedrockUuid != null) {
                return legacyBedrockUuid;
            }
        }
        if (account != null && account.getPlayerUuid() != null) {
            return account.getPlayerUuid();
        }
        return liveUniqueId;
    }

    private boolean syncPlayerUuid(AccountRecord account, UUID liveUniqueId, boolean detectedBedrock) {
        if (account == null) {
            return false;
        }
        UUID resolvedPlayerUuid = resolvePlayerUuid(account, liveUniqueId, detectedBedrock);
        if (resolvedPlayerUuid == null || resolvedPlayerUuid.equals(account.getPlayerUuid())) {
            return false;
        }
        account.setPlayerUuid(resolvedPlayerUuid);
        return true;
    }

    private boolean shouldUseBedrockUuid(AccountRecord account, boolean detectedBedrock) {
        if (account != null && account.getAccountType() == AccountType.BEDROCK) {
            return true;
        }
        return detectedBedrock && (account == null || account.getAccountType() != AccountType.PREMIUM);
    }

    private UUID resolveLegacyBedrockUniqueId(UUID storedPlayerUuid, UUID liveUniqueId) {
        if (isLegacyBedrockUniqueId(storedPlayerUuid)) {
            return storedPlayerUuid;
        }
        UUID floodgateLegacyUuid = floodgateDetector.resolveLegacyBedrockUniqueId(liveUniqueId);
        if (floodgateLegacyUuid != null) {
            return floodgateLegacyUuid;
        }
        return storedPlayerUuid;
    }

    private boolean isLegacyBedrockUniqueId(UUID uniqueId) {
        return uniqueId != null && uniqueId.getMostSignificantBits() == 0L;
    }

    private UUID resolveProxyUniqueId(AccountRecord account) {
        return resolveProxyUniqueId(account, null);
    }

    private UUID resolveProxyUniqueId(AccountRecord account, UUID liveUniqueId) {
        if (account.getAccountType() == AccountType.PREMIUM) {
            if (config.premium().existingPremiumUuidMode() == PremiumUuidMode.REAL && account.getPremiumUuid() != null) {
                return account.getPremiumUuid();
            }
            if (account.getPlayerUuid() != null) {
                return account.getPlayerUuid();
            }
            return account.getPremiumUuid();
        }
        return resolvePlayerUuid(account, liveUniqueId, account.getAccountType() == AccountType.BEDROCK);
    }

    UUID resolveBackendUniqueId(ProxiedPlayer player) {
        AuthSession session = sessions.get(player.getUniqueId());
        if (session != null && session.getAccount() != null) {
            return resolveBackendUniqueId(session.getAccount(), player.getUniqueId());
        }
        return connectionIdentityAccessor.readRewriteId(player);
    }

    private UUID resolveBackendUniqueId(AccountRecord account) {
        return resolveBackendUniqueId(account, null);
    }

    private UUID resolveBackendUniqueId(AccountRecord account, UUID liveUniqueId) {
        return resolveProxyUniqueId(account, liveUniqueId);
    }

    private void applyConnectionIdentity(PendingConnection connection, AccountRecord account) {
        if (connection == null || account == null) {
            return;
        }

        UUID liveUniqueId = connection.getUniqueId();
        UUID proxyUniqueId = resolveProxyUniqueId(account, liveUniqueId);
        UUID backendUniqueId = resolveBackendUniqueId(account, liveUniqueId);
        connectionIdentityAccessor.apply(connection, proxyUniqueId, backendUniqueId);
    }

    private void applyPlayerIdentity(ProxiedPlayer player, AccountRecord account) {
        if (player == null || account == null) {
            return;
        }

        UUID liveUniqueId = player.getUniqueId();
        UUID proxyUniqueId = resolveProxyUniqueId(account, liveUniqueId);
        UUID backendUniqueId = resolveBackendUniqueId(account, liveUniqueId);
        connectionIdentityAccessor.apply(player, proxyUniqueId, backendUniqueId);
    }

    private String formatDuration(long totalSeconds) {
        long seconds = Math.max(0L, totalSeconds);
        long hours = seconds / 3600L;
        long minutes = (seconds % 3600L) / 60L;
        long remainingSeconds = seconds % 60L;

        if (hours > 0L) {
            return hours + "h " + minutes + "m " + remainingSeconds + "s";
        }
        if (minutes > 0L) {
            return minutes + "m " + remainingSeconds + "s";
        }
        return remainingSeconds + "s";
    }

    private boolean isBedrockPlayer(PendingConnection connection) {
        if (connection == null) {
            return false;
        }
        return isBedrockPlayer(connection.getUniqueId(), connection.getName());
    }

    private boolean isBedrockPlayer(String playerName) {
        return isBedrockPlayer(null, playerName);
    }

    private boolean isBedrockPlayer(UUID playerUuid, String playerName) {
        if (!config.bedrock().enabled()) {
            return false;
        }
        if (isBedrockUsername(playerName)) {
            return true;
        }
        return floodgateDetector.isFloodgatePlayer(playerUuid);
    }

    private boolean isBedrockUsername(String playerName) {
        if (playerName == null || playerName.isBlank()) {
            return false;
        }
        String normalized = playerName.toLowerCase();
        for (String prefix : config.bedrock().autoLoginPrefixes()) {
            if (!prefix.isBlank() && normalized.startsWith(prefix.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private final class FloodgateDetector {
        private volatile boolean initialized;
        private volatile Method getInstanceMethod;
        private volatile Method isFloodgatePlayerMethod;
        private volatile Method getPlayerMethod;
        private volatile boolean warningLogged;
        private volatile boolean identityWarningLogged;
        private volatile boolean xuidWarningLogged;

        boolean isFloodgatePlayer(UUID playerUuid) {
            if (playerUuid == null) {
                return false;
            }

            ensureInitialized();
            if (getInstanceMethod == null || isFloodgatePlayerMethod == null) {
                return false;
            }

            try {
                Object api = getInstanceMethod.invoke(null);
                return Boolean.TRUE.equals(isFloodgatePlayerMethod.invoke(api, playerUuid));
            } catch (ReflectiveOperationException exception) {
                if (!warningLogged) {
                    warningLogged = true;
                    plugin.getLogger().warning("Floodgate API lookup failed, Bedrock auto-detection will fall back to prefixes only: "
                            + exception.getMessage());
                }
                return false;
            }
        }

        UUID resolveLegacyBedrockUniqueId(UUID playerUuid) {
            String xuid = resolveXuid(playerUuid);
            if (xuid == null) {
                return null;
            }

            try {
                return new UUID(0L, Long.parseUnsignedLong(xuid));
            } catch (NumberFormatException exception) {
                if (!xuidWarningLogged) {
                    xuidWarningLogged = true;
                    plugin.getLogger().warning("Floodgate XUID '" + xuid + "' is not numeric, Bedrock legacy UUID rewrite is disabled.");
                }
                return null;
            }
        }

        private String resolveXuid(UUID playerUuid) {
            if (playerUuid == null) {
                return null;
            }

            ensureInitialized();
            if (getInstanceMethod == null || getPlayerMethod == null) {
                return null;
            }

            try {
                Object api = getInstanceMethod.invoke(null);
                Object floodgatePlayer = getPlayerMethod.invoke(api, playerUuid);
                if (floodgatePlayer == null) {
                    return null;
                }

                Method getXuidMethod = floodgatePlayer.getClass().getMethod("getXuid");
                Object xuid = getXuidMethod.invoke(floodgatePlayer);
                if (xuid instanceof String value && !value.isBlank()) {
                    return value;
                }
            } catch (ReflectiveOperationException exception) {
                if (!identityWarningLogged) {
                    identityWarningLogged = true;
                    plugin.getLogger().warning("Floodgate XUID lookup failed, Bedrock UUIDs will stay on the stored value: "
                            + exception.getMessage());
                }
            }
            return null;
        }

        private synchronized void ensureInitialized() {
            if (initialized) {
                return;
            }
            initialized = true;

            try {
                Class<?> apiClass = Class.forName("org.geysermc.floodgate.api.FloodgateApi");
                getInstanceMethod = apiClass.getMethod("getInstance");
                isFloodgatePlayerMethod = apiClass.getMethod("isFloodgatePlayer", UUID.class);
                getPlayerMethod = apiClass.getMethod("getPlayer", UUID.class);
            } catch (ClassNotFoundException | NoSuchMethodException ignored) {
                getInstanceMethod = null;
                isFloodgatePlayerMethod = null;
                getPlayerMethod = null;
            }
        }
    }

    private final class ConnectionIdentityAccessor {
        private volatile boolean pendingInitialized;
        private volatile boolean playerInitialized;
        private volatile Field pendingUniqueIdField;
        private volatile Field pendingRewriteIdField;
        private volatile Field pendingOfflineIdField;
        private volatile Field playerUniqueIdField;
        private volatile Field playerRewriteIdField;
        private volatile Field playerOfflineIdField;
        private volatile Method playerRewriteIdMethod;
        private volatile boolean warningLogged;

        void apply(PendingConnection connection, UUID uniqueId, UUID rewriteId) {
            if (connection == null || (uniqueId == null && rewriteId == null)) {
                return;
            }

            ensurePendingInitialized(connection.getClass());
            UUID effectiveOfflineId = rewriteId != null ? rewriteId : uniqueId;
            if (!connection.isOnlineMode() && uniqueId != null) {
                try {
                    connection.setUniqueId(uniqueId);
                } catch (IllegalStateException ignored) {
                    // Fall through to reflective write when Travertine rejects API-based updates.
                }
            }

            try {
                if (pendingUniqueIdField != null && uniqueId != null) {
                    pendingUniqueIdField.set(connection, uniqueId);
                }
                if (pendingRewriteIdField != null && rewriteId != null) {
                    pendingRewriteIdField.set(connection, rewriteId);
                }
                if (pendingOfflineIdField != null && effectiveOfflineId != null) {
                    pendingOfflineIdField.set(connection, effectiveOfflineId);
                }
            } catch (IllegalAccessException exception) {
                logWarningOnce("Unable to apply connection UUID identity", exception);
            }
        }

        void apply(ProxiedPlayer player, UUID uniqueId, UUID rewriteId) {
            if (player == null || (uniqueId == null && rewriteId == null)) {
                return;
            }

            apply(player.getPendingConnection(), uniqueId, rewriteId);
            ensurePlayerInitialized(player.getClass());
            UUID effectiveOfflineId = rewriteId != null ? rewriteId : uniqueId;

            try {
                if (playerUniqueIdField != null && uniqueId != null) {
                    playerUniqueIdField.set(player, uniqueId);
                }
                if (playerRewriteIdField != null && rewriteId != null) {
                    playerRewriteIdField.set(player, rewriteId);
                }
                if (playerOfflineIdField != null && effectiveOfflineId != null) {
                    playerOfflineIdField.set(player, effectiveOfflineId);
                }
            } catch (IllegalAccessException exception) {
                logWarningOnce("Unable to apply player UUID identity", exception);
            }
        }

        UUID readRewriteId(ProxiedPlayer player) {
            if (player == null) {
                return null;
            }

            ensurePlayerInitialized(player.getClass());
            if (playerRewriteIdMethod == null) {
                try {
                    UUID rewrittenUniqueId = readUuidField(playerRewriteIdField, player);
                    if (rewrittenUniqueId != null) {
                        return rewrittenUniqueId;
                    }
                } catch (IllegalAccessException exception) {
                    logWarningOnce("Unable to read backend rewrite UUID", exception);
                }
                return player.getUniqueId();
            }

            try {
                Object value = playerRewriteIdMethod.invoke(player);
                return value instanceof UUID uuid ? uuid : player.getUniqueId();
            } catch (ReflectiveOperationException exception) {
                logWarningOnce("Unable to read backend rewrite UUID", exception);
                return player.getUniqueId();
            }
        }

        private synchronized void ensurePendingInitialized(Class<?> pendingConnectionClass) {
            if (pendingInitialized) {
                return;
            }
            pendingInitialized = true;
            pendingUniqueIdField = findField(pendingConnectionClass, "uniqueId");
            pendingRewriteIdField = findField(pendingConnectionClass, "rewriteId");
            pendingOfflineIdField = findField(pendingConnectionClass, "offlineId");
        }

        private synchronized void ensurePlayerInitialized(Class<?> playerClass) {
            if (playerInitialized) {
                return;
            }
            playerInitialized = true;
            playerUniqueIdField = findField(playerClass, "uniqueId");
            playerRewriteIdField = findField(playerClass, "rewriteId");
            playerOfflineIdField = findField(playerClass, "offlineId");
            playerRewriteIdMethod = findMethod(playerClass, "getRewriteId");
        }

        private UUID readUuidField(Field field, Object target) throws IllegalAccessException {
            if (field == null || target == null) {
                return null;
            }
            Object value = field.get(target);
            return value instanceof UUID uuid ? uuid : null;
        }

        private Field findField(Class<?> type, String name) {
            Class<?> current = type;
            while (current != null) {
                try {
                    Field field = current.getDeclaredField(name);
                    field.setAccessible(true);
                    return field;
                } catch (NoSuchFieldException ignored) {
                    current = current.getSuperclass();
                }
            }
            return null;
        }

        private Method findMethod(Class<?> type, String name) {
            Class<?> current = type;
            while (current != null) {
                try {
                    Method method = current.getDeclaredMethod(name);
                    method.setAccessible(true);
                    return method;
                } catch (NoSuchMethodException ignored) {
                    current = current.getSuperclass();
                }
            }
            return null;
        }

        private void logWarningOnce(String message, ReflectiveOperationException exception) {
            if (!warningLogged) {
                warningLogged = true;
                plugin.getLogger().warning(message + ": " + exception.getMessage());
            }
        }
    }

    private final class StaleConnectionAccessor {
        private volatile boolean proxyInitialized;
        private volatile boolean pendingInitialized;
        private volatile Method removeConnectionMethod;
        private volatile Method getPlayerByOfflineUuidMethod;
        private volatile Method getOfflineIdMethod;
        private volatile Field connectionsField;
        private volatile Field connectionsByUUIDField;
        private volatile Field connectionsByOfflineUUIDField;
        private volatile Field connectionLockField;
        private volatile boolean warningLogged;

        UUID readOfflineId(PendingConnection connection) {
            if (connection == null) {
                return null;
            }

            ensurePendingInitialized(connection.getClass());
            if (getOfflineIdMethod == null) {
                return null;
            }

            try {
                Object value = getOfflineIdMethod.invoke(connection);
                return value instanceof UUID uuid ? uuid : null;
            } catch (ReflectiveOperationException exception) {
                logWarningOnce("Unable to read pending offline UUID", exception);
                return null;
            }
        }

        ProxiedPlayer findByOfflineId(Object proxy, UUID offlineId) {
            if (proxy == null || offlineId == null) {
                return null;
            }

            ensureProxyInitialized(proxy.getClass());
            if (getPlayerByOfflineUuidMethod == null) {
                return null;
            }

            try {
                Object value = getPlayerByOfflineUuidMethod.invoke(proxy, offlineId);
                return value instanceof ProxiedPlayer player ? player : null;
            } catch (ReflectiveOperationException exception) {
                logWarningOnce("Unable to look up proxy connection by offline UUID", exception);
                return null;
            }
        }

        boolean remove(Object proxy, ProxiedPlayer player) {
            if (proxy == null || player == null) {
                return false;
            }

            ensureProxyInitialized(proxy.getClass());

            if (removeConnectionMethod != null) {
                try {
                    removeConnectionMethod.invoke(proxy, player);
                } catch (ReflectiveOperationException | IllegalArgumentException exception) {
                    logWarningOnce("Unable to remove stale proxy connection through proxy API", exception);
                }
            }

            if (!isStillRegistered(proxy, player)) {
                return true;
            }

            return removeDirectly(proxy, player);
        }

        private boolean isStillRegistered(Object proxy, ProxiedPlayer player) {
            if (plugin.getProxy().getPlayer(player.getName()) == player) {
                return true;
            }
            if (plugin.getProxy().getPlayer(player.getUniqueId()) == player) {
                return true;
            }

            UUID offlineId = readOfflineId(player.getPendingConnection());
            return findByOfflineId(proxy, offlineId) == player;
        }

        @SuppressWarnings("unchecked")
        private boolean removeDirectly(Object proxy, ProxiedPlayer player) {
            Lock writeLock = lockConnections(proxy);
            try {
                boolean removed = false;
                removed |= removeFromMap((Map<Object, Object>) readField(connectionsField, proxy), player.getName(), player);
                removed |= removeFromMap((Map<Object, Object>) readField(connectionsByUUIDField, proxy), player.getUniqueId(), player);
                removed |= removeFromMap((Map<Object, Object>) readField(connectionsByOfflineUUIDField, proxy),
                        readOfflineId(player.getPendingConnection()), player);
                return removed && !isStillRegistered(proxy, player);
            } catch (IllegalAccessException exception) {
                logWarningOnce("Unable to remove stale proxy connection directly", exception);
                return false;
            } finally {
                if (writeLock != null) {
                    writeLock.unlock();
                }
            }
        }

        private Lock lockConnections(Object proxy) {
            if (connectionLockField == null) {
                return null;
            }

            try {
                Object lock = connectionLockField.get(proxy);
                if (lock instanceof ReadWriteLock readWriteLock) {
                    Lock writeLock = readWriteLock.writeLock();
                    writeLock.lock();
                    return writeLock;
                }
            } catch (IllegalAccessException exception) {
                logWarningOnce("Unable to lock proxy connection state", exception);
            }
            return null;
        }

        private Object readField(Field field, Object target) throws IllegalAccessException {
            if (field == null || target == null) {
                return null;
            }
            return field.get(target);
        }

        private boolean removeFromMap(Map<Object, Object> map, Object key, ProxiedPlayer player) {
            if (map == null || player == null) {
                return false;
            }

            boolean removed = false;
            if (key != null && map.get(key) == player) {
                map.remove(key);
                removed = true;
            }

            if (removed) {
                return true;
            }

            var iterator = map.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<Object, Object> entry = iterator.next();
                if (entry.getValue() == player) {
                    iterator.remove();
                    removed = true;
                }
            }
            return removed;
        }

        private synchronized void ensureProxyInitialized(Class<?> proxyClass) {
            if (proxyInitialized) {
                return;
            }
            proxyInitialized = true;

            removeConnectionMethod = findMethodByName(proxyClass, "removeConnection", 1);
            getPlayerByOfflineUuidMethod = findMethod(proxyClass, "getPlayerByOfflineUUID", UUID.class);
            connectionsField = findField(proxyClass, "connections");
            connectionsByUUIDField = findField(proxyClass, "connectionsByUUID");
            connectionsByOfflineUUIDField = findField(proxyClass, "connectionsByOfflineUUID");
            connectionLockField = findField(proxyClass, "connectionLock");
        }

        private synchronized void ensurePendingInitialized(Class<?> pendingConnectionClass) {
            if (pendingInitialized) {
                return;
            }
            pendingInitialized = true;
            getOfflineIdMethod = findMethod(pendingConnectionClass, "getOfflineId");
        }

        private Field findField(Class<?> type, String name) {
            Class<?> current = type;
            while (current != null) {
                try {
                    Field field = current.getDeclaredField(name);
                    field.setAccessible(true);
                    return field;
                } catch (NoSuchFieldException ignored) {
                    current = current.getSuperclass();
                }
            }
            return null;
        }

        private Method findMethod(Class<?> type, String name, Class<?>... parameterTypes) {
            Class<?> current = type;
            while (current != null) {
                try {
                    Method method = current.getDeclaredMethod(name, parameterTypes);
                    method.setAccessible(true);
                    return method;
                } catch (NoSuchMethodException ignored) {
                    current = current.getSuperclass();
                }
            }
            return null;
        }

        private Method findMethodByName(Class<?> type, String name, int parameterCount) {
            Class<?> current = type;
            while (current != null) {
                for (Method method : current.getDeclaredMethods()) {
                    if (method.getName().equals(name) && method.getParameterCount() == parameterCount) {
                        method.setAccessible(true);
                        return method;
                    }
                }
                current = current.getSuperclass();
            }
            return null;
        }

        private void logWarningOnce(String message, Exception exception) {
            if (!warningLogged) {
                warningLogged = true;
                plugin.getLogger().warning(message + ": " + exception.getMessage());
            }
        }
    }

    private static final class PremiumAuthenticationRequiredException extends RuntimeException {
    }

    private static final class PremiumVerificationUnavailableException extends RuntimeException {
    }
}
