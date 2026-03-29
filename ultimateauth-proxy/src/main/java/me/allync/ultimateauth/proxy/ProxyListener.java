package me.allync.ultimateauth.proxy;

import net.md_5.bungee.api.connection.PendingConnection;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.event.ChatEvent;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.event.PlayerHandshakeEvent;
import net.md_5.bungee.api.event.PostLoginEvent;
import net.md_5.bungee.api.event.PreLoginEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;
import net.md_5.bungee.api.event.ServerKickEvent;
import net.md_5.bungee.api.event.ServerSwitchEvent;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.event.EventHandler;

import java.util.Locale;
import java.util.Map;

public final class ProxyListener implements Listener {
    private final PluginConfig config;
    private final MessageBundle messages;
    private final AuthService authService;

    ProxyListener(PluginConfig config, MessageBundle messages, AuthService authService) {
        this.config = config;
        this.messages = messages;
        this.authService = authService;
    }

    @EventHandler
    public void onPreLogin(PreLoginEvent event) {
        if (config.network().acceptedHostnames().isEmpty()) {
            authService.handlePreLogin(event);
            return;
        }

        PendingConnection connection = event.getConnection();
        if (connection.getVirtualHost() != null) {
            String hostname = connection.getVirtualHost().getHostString().toLowerCase(Locale.ROOT);
            if (!config.network().acceptedHostnames().contains(hostname)) {
                event.setCancelled(true);
                event.setCancelReason(messages.components(messages.render("errors.hostname_blocked", Map.of())));
                return;
            }
        }

        authService.handlePreLogin(event);
    }

    @EventHandler
    public void onHandshake(PlayerHandshakeEvent event) {
        authService.handleHandshake(event.getConnection());
    }

    @EventHandler
    public void onLogin(LoginEvent event) {
        authService.handleLogin(event);
    }

    @EventHandler
    public void onPostLogin(PostLoginEvent event) {
        authService.handlePostLogin(event);
    }

    @EventHandler
    public void onServerConnect(ServerConnectEvent event) {
        ProxiedPlayer player = event.getPlayer();
        if (!authService.shouldBlock(player)) {
            return;
        }

        var limbo = authService.resolveLimboServer();
        if (limbo == null) {
            player.disconnect(messages.components(messages.render("errors.limbo_missing", Map.of())));
            return;
        }
        event.setTarget(limbo);
    }

    @EventHandler
    public void onServerSwitch(ServerSwitchEvent event) {
        authService.handleServerSwitch(event.getPlayer());
    }

    @EventHandler
    public void onChat(ChatEvent event) {
        if (!(event.getSender() instanceof ProxiedPlayer player) || !authService.shouldBlock(player)) {
            return;
        }

        if (!event.isCommand()) {
            event.setCancelled(true);
            messages.send(player, "errors.chat_blocked");
            return;
        }

        String message = event.getMessage().startsWith("/") ? event.getMessage().substring(1) : event.getMessage();
        String command = message.split(" ", 2)[0].toLowerCase(Locale.ROOT);
        if (!authService.isAllowedUnauthenticatedCommand(command)) {
            event.setCancelled(true);
            messages.send(player, "errors.command_blocked");
        }
    }

    @EventHandler
    public void onServerKick(ServerKickEvent event) {
        if (!config.network().redirectOnKick()) {
            return;
        }

        var fallback = authService.isAuthenticated(event.getPlayer())
                ? authService.resolveAuthorizedServerFor(event.getPlayer())
                : authService.resolveLimboServer();

        if (fallback == null || event.getKickedFrom() == null || fallback.getName().equalsIgnoreCase(event.getKickedFrom().getName())) {
            return;
        }

        event.setCancelled(true);
        event.setCancelServer(fallback);
    }

    @EventHandler
    public void onDisconnect(PlayerDisconnectEvent event) {
        authService.handleDisconnect(event.getPlayer());
    }
}
