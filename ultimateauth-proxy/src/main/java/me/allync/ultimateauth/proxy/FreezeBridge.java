package me.allync.ultimateauth.proxy;

import net.md_5.bungee.api.connection.ProxiedPlayer;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

final class FreezeBridge {
    private final UltimateAuthPlugin plugin;
    private final PluginConfig config;

    FreezeBridge(UltimateAuthPlugin plugin, PluginConfig config) {
        this.plugin = plugin;
        this.config = config;
    }

    void registerChannel() {
        if (config.backendBridge().enabled()) {
            plugin.getProxy().registerChannel(config.backendBridge().pluginChannel());
        }
    }

    void unregisterChannel() {
        if (config.backendBridge().enabled()) {
            plugin.getProxy().unregisterChannel(config.backendBridge().pluginChannel());
        }
    }

    void pushState(ProxiedPlayer player, boolean frozen) {
        if (!config.backendBridge().enabled() || player.getServer() == null) {
            return;
        }

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(byteArrayOutputStream)) {
                output.writeUTF(config.network().accessToken());
                output.writeUTF(player.getUniqueId().toString());
                output.writeBoolean(frozen);
            }
            player.getServer().getInfo().sendData(config.backendBridge().pluginChannel(), byteArrayOutputStream.toByteArray());
        } catch (IOException exception) {
            plugin.getLogger().warning("Unable to push auth state for " + player.getName() + ": " + exception.getMessage());
        }
    }
}
