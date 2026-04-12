package me.allync.ultimateauth.proxy;

import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Command;
import net.md_5.bungee.api.plugin.Plugin;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class UltimateAuthPlugin extends Plugin {
    private ExecutorService databaseExecutor;
    private PluginConfig pluginConfig;
    private MessageBundle messages;
    private DatabaseManager databaseManager;
    private FreezeBridge freezeBridge;
    private AuthService authService;

    @Override
    public void onEnable() {
        try {
            if (!getDataFolder().exists() && !getDataFolder().mkdirs()) {
                throw new IOException("Unable to create plugin data directory");
            }

            copyDefaultResource("config.yml");
            copyDefaultResource("messages.yml");

            pluginConfig = PluginConfig.load(new File(getDataFolder(), "config.yml"));
            messages = MessageBundle.load(new File(getDataFolder(), "messages.yml"));
            databaseExecutor = Executors.newFixedThreadPool(4);

            PasswordService passwordService = new PasswordService();
            MojangService mojangService = new MojangService(this);
            databaseManager = new DatabaseManager(this, pluginConfig, passwordService);
            databaseManager.initialize();

            freezeBridge = new FreezeBridge(this, pluginConfig);
            freezeBridge.registerChannel();

            authService = new AuthService(this, pluginConfig, messages, databaseManager, passwordService, mojangService, freezeBridge);
            freezeBridge.setAuthService(authService);

            getProxy().getPluginManager().registerListener(this, new ProxyListener(pluginConfig, messages, authService));
            registerCommands();
            getLogger().info("UltimateAuth proxy module enabled.");
        } catch (Exception exception) {
            throw new RuntimeException("Unable to enable UltimateAuth", exception);
        }
    }

    @Override
    public void onDisable() {
        if (freezeBridge != null) {
            freezeBridge.unregisterChannel();
        }
        if (databaseManager != null) {
            databaseManager.close();
        }
        if (databaseExecutor != null) {
            databaseExecutor.shutdownNow();
        }
    }

    ExecutorService getDatabaseExecutor() {
        return databaseExecutor;
    }

    private void registerCommands() {
        getProxy().getPluginManager().registerCommand(this, new SimpleCommand(
                "register",
                null,
                new String[0],
                (sender, args) -> {
                    ProxiedPlayer player = requirePlayer(sender);
                    if (player == null) {
                        return;
                    }
                    if (args.length != 1) {
                        messages.send(sender, "usage.register");
                        return;
                    }
                    authService.attemptRegister(player, args[0]);
                }
        ));

        getProxy().getPluginManager().registerCommand(this, new SimpleCommand(
                "login",
                null,
                pluginConfig.authorization().loginAliases().toArray(String[]::new),
                (sender, args) -> {
                    ProxiedPlayer player = requirePlayer(sender);
                    if (player == null) {
                        return;
                    }
                    if (args.length != 1) {
                        messages.send(sender, "usage.login");
                        return;
                    }
                    authService.attemptLogin(player, args[0]);
                }
        ));

        getProxy().getPluginManager().registerCommand(this, new SimpleCommand(
                "premium",
                null,
                new String[0],
                (sender, args) -> {
                    ProxiedPlayer player = requirePlayer(sender);
                    if (player == null) {
                        return;
                    }
                    if (args.length == 0) {
                        messages.send(sender, "auth.premium_confirm");
                        return;
                    }
                    if (args.length != 1 || !"confirm".equalsIgnoreCase(args[0])) {
                        messages.send(sender, "usage.premium");
                        return;
                    }
                    authService.switchToPremium(player);
                }
        ));

        getProxy().getPluginManager().registerCommand(this, new SimpleCommand(
                "cracked",
                null,
                new String[0],
                (sender, args) -> {
                    ProxiedPlayer player = requirePlayer(sender);
                    if (player == null) {
                        return;
                    }
                    if (args.length != 0) {
                        messages.send(sender, "usage.cracked");
                        return;
                    }
                    authService.switchToCracked(player);
                }
        ));

        getProxy().getPluginManager().registerCommand(this, new SimpleCommand(
                "changepassword",
                null,
                new String[]{"changepass"},
                (sender, args) -> {
                    ProxiedPlayer player = requirePlayer(sender);
                    if (player == null) {
                        return;
                    }
                    if (args.length != 2) {
                        messages.send(sender, "usage.change_password");
                        return;
                    }
                    authService.changePassword(player, args[0], args[1]);
                }
        ));

        getProxy().getPluginManager().registerCommand(this, new SimpleCommand(
                "forcepremium",
                "ultimateauth.command.forcepremium",
                new String[0],
                (sender, args) -> {
                    if (args.length != 1) {
                        messages.send(sender, "usage.forcepremium");
                        return;
                    }
                    authService.forcePremium(sender, args[0]);
                }
        ));

        getProxy().getPluginManager().registerCommand(this, new SimpleCommand(
                "forcecracked",
                "ultimateauth.command.forcecracked",
                new String[0],
                (sender, args) -> {
                    if (args.length != 1) {
                        messages.send(sender, "usage.forcecracked");
                        return;
                    }
                    authService.forceCracked(sender, args[0]);
                }
        ));

        getProxy().getPluginManager().registerCommand(this, new SimpleCommand(
                "forceunregister",
                "ultimateauth.command.forceunregister",
                new String[0],
                (sender, args) -> {
                    if (args.length != 1) {
                        messages.send(sender, "usage.forceunregister");
                        return;
                    }
                    authService.forceUnregister(sender, args[0]);
                }
        ));

        getProxy().getPluginManager().registerCommand(this, new SimpleCommand(
                "forceregister",
                "ultimateauth.command.forceregister",
                new String[0],
                (sender, args) -> {
                    if (args.length < 1 || args.length > 2) {
                        messages.send(sender, "usage.forceregister");
                        return;
                    }
                    authService.forceRegister(sender, args[0], args.length == 2 ? args[1] : null);
                }
        ));
    }

    private ProxiedPlayer requirePlayer(CommandSender sender) {
        if (sender instanceof ProxiedPlayer player) {
            return player;
        }
        messages.send(sender, "errors.player_only");
        return null;
    }

    private void copyDefaultResource(String resourceName) throws IOException {
        File target = new File(getDataFolder(), resourceName);
        if (target.exists()) {
            return;
        }
        try (InputStream stream = getResourceAsStream(resourceName)) {
            if (stream == null) {
                throw new IOException("Missing bundled resource " + resourceName);
            }
            Files.copy(stream, target.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private interface CommandExecutor {
        void execute(CommandSender sender, String[] args);
    }

    private final class SimpleCommand extends Command {
        private final CommandExecutor executor;

        private SimpleCommand(String name, String permission, String[] aliases, CommandExecutor executor) {
            super(name, permission, aliases);
            this.executor = executor;
        }

        @Override
        public void execute(CommandSender sender, String[] args) {
            if (getPermission() != null && !getPermission().isBlank() && !sender.hasPermission(getPermission())) {
                messages.send(sender, "errors.no_permission");
                return;
            }
            executor.execute(sender, Arrays.copyOf(args, args.length));
        }
    }
}
