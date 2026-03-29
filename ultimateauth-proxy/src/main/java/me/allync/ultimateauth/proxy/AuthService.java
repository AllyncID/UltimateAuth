package me.allync.ultimateauth.proxy;

import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.config.ServerInfo;
import net.md_5.bungee.api.connection.PendingConnection;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.event.PreLoginEvent;
import net.md_5.bungee.api.event.PostLoginEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
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
    private final ConcurrentHashMap<String, FailedLoginWindow> failedLoginWindows = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();

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
                PreparedLogin preparedLogin = prepareLogin(username, connection.getUniqueId(), extractIp(connection.getSocketAddress()), connection.isOnlineMode());
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

        event.registerIntent(plugin);
        plugin.getDatabaseExecutor().execute(() -> {
            try {
                Optional<AccountRecord> loaded = database.loadAccount(playerName);
                if (loaded.isPresent()) {
                    AccountRecord account = loaded.get();
                    if (account.getAccountType() == AccountType.PREMIUM) {
                        connection.setOnlineMode(true);
                    }
                    if (account.getPlayerUuid() != null) {
                        connection.setUniqueId(account.getPlayerUuid());
                    }
                }
            } catch (Exception exception) {
                plugin.getLogger().warning("Unable to prepare pre-login UUID for " + playerName + ": " + exception.getMessage());
            } finally {
                event.completeIntent(plugin);
            }
        });
    }

    void handleHandshake(PendingConnection connection) {
        String playerName = connection.getName();
        if (playerName == null || playerName.isBlank()) {
            return;
        }

        try {
            Optional<AccountRecord> loaded = database.loadAccount(playerName);
            if (loaded.isPresent() && loaded.get().getAccountType() == AccountType.PREMIUM) {
                connection.setOnlineMode(true);
                return;
            }
            if (loaded.isPresent() || !config.premium().autoDetectNames()
                    || !config.premium().protectUnregisteredNames() || isBedrockPlayer(playerName)) {
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
            clearFailedLoginWindow(finalAccount.getUsernameLower());
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
            clearFailedLoginWindow(account.getUsernameLower());
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
            clearFailedLoginWindow(account.getUsernameLower());
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
            clearFailedLoginWindow(account.getUsernameLower());
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

    private PreparedLogin prepareLogin(String playerName, UUID playerUuid, String ipAddress, boolean onlineMode) {
        long now = System.currentTimeMillis();
        boolean bedrockPlayer = isBedrockPlayer(playerName);
        Optional<AccountRecord> loaded = database.loadAccount(playerName);
        AccountRecord account = loaded.orElse(null);

        if (account == null) {
            if (bedrockPlayer) {
                account = database.newAccount(playerName, playerUuid);
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
        if (account.getPlayerUuid() == null) {
            account.setPlayerUuid(playerUuid);
        }

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
                account = database.newAccount(playerName, playerUuid);
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
        if (account.getPlayerUuid() == null) {
            account.setPlayerUuid(playerUuid);
        }

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
        clearFailedLoginWindow(account.getUsernameLower());

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
            clearFailedLoginWindow(account.getUsernameLower());
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
        String usernameLower = account.getUsernameLower();
        if (isLoginLocked(usernameLower, maxTries)) {
            String waitTime = formatDuration(remainingLockSeconds(usernameLower));
            messages.send(player, "errors.login_locked", Map.of("%time%", waitTime));
            player.disconnect(messages.components(messages.render("errors.login_locked", Map.of("%time%", waitTime))));
            return;
        }

        if (!passwordService.matches(password, account)) {
            if (maxTries <= 0) {
                session.incrementFailedLoginAttempts();
                messages.send(player, "errors.password_wrong", Map.of("%tries%", "∞"));
                return;
            }

            int attempts = recordFailedLoginAttempt(usernameLower);
            int remaining = Math.max(0, maxTries - attempts);
            if (attempts >= maxTries) {
                String waitTime = formatDuration(remainingLockSeconds(usernameLower));
                messages.send(player, "errors.login_locked", Map.of("%time%", waitTime));
                player.disconnect(messages.components(messages.render("errors.login_locked", Map.of("%time%", waitTime))));
                return;
            }

            session.incrementFailedLoginAttempts();
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
            clearFailedLoginWindow(account.getUsernameLower());

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
            clearFailedLoginWindow(account.getUsernameLower());
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

    private int recordFailedLoginAttempt(String usernameLower) {
        FailedLoginWindow window = failedLoginWindows.compute(usernameLower, (key, current) -> {
            long now = System.currentTimeMillis();
            long expiresAt = now + failedLoginWindowMillis();
            if (current == null || current.expiresAt() <= now) {
                return new FailedLoginWindow(1, expiresAt);
            }
            return new FailedLoginWindow(current.attempts() + 1, expiresAt);
        });
        return window == null ? 0 : window.attempts();
    }

    private boolean isLoginLocked(String usernameLower, int maxTries) {
        if (maxTries <= 0) {
            return false;
        }

        FailedLoginWindow window = failedLoginWindows.get(usernameLower);
        if (window == null) {
            return false;
        }

        long now = System.currentTimeMillis();
        if (window.expiresAt() <= now) {
            failedLoginWindows.remove(usernameLower, window);
            return false;
        }
        return window.attempts() >= maxTries;
    }

    private long remainingLockSeconds(String usernameLower) {
        FailedLoginWindow window = failedLoginWindows.get(usernameLower);
        if (window == null) {
            return 0L;
        }
        return Math.max(1L, TimeUnit.MILLISECONDS.toSeconds(Math.max(0L, window.expiresAt() - System.currentTimeMillis())));
    }

    private void clearFailedLoginWindow(String usernameLower) {
        failedLoginWindows.remove(usernameLower);
    }

    private long failedLoginWindowMillis() {
        return TimeUnit.SECONDS.toMillis(Math.max(30, config.authorization().maximumAuthorisationTimeSeconds()));
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

    private boolean isBedrockPlayer(String playerName) {
        if (!config.bedrock().enabled()) {
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

    private record FailedLoginWindow(int attempts, long expiresAt) {
    }

    private static final class PremiumAuthenticationRequiredException extends RuntimeException {
    }

    private static final class PremiumVerificationUnavailableException extends RuntimeException {
    }
}
