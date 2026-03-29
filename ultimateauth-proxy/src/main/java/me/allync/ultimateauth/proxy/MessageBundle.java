package me.allync.ultimateauth.proxy;

import net.md_5.bungee.api.ChatColor;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.Title;
import net.md_5.bungee.api.chat.BaseComponent;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;
import net.md_5.bungee.config.YamlConfiguration;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

final class MessageBundle {
    private final Configuration configuration;

    private MessageBundle(Configuration configuration) {
        this.configuration = configuration;
    }

    static MessageBundle load(File file) throws IOException {
        return new MessageBundle(ConfigurationProvider.getProvider(YamlConfiguration.class).load(file));
    }

    void send(CommandSender sender, String path) {
        send(sender, path, Map.of());
    }

    void send(CommandSender sender, String path, Map<String, String> placeholders) {
        sender.sendMessage(components(render(path, placeholders)));
    }

    void sendTitle(ProxiedPlayer player, String key, Map<String, String> placeholders) {
        TitleSettings settings = titleSettings(key, 0L, 0, false);
        if (!settings.enabled()) {
            return;
        }

        String titleText = render("titles." + key + ".title", placeholders);
        String subtitleText = render("titles." + key + ".subtitle", placeholders);

        if (strip(titleText).isBlank() && strip(subtitleText).isBlank()) {
            return;
        }

        Title title = ProxyServer.getInstance().createTitle();
        if (settings.resetBeforeSend()) {
            title.reset();
        }
        title.title(components(titleText))
                .subTitle(components(subtitleText))
                .fadeIn(settings.fadeIn())
                .stay(settings.stay())
                .fadeOut(settings.fadeOut());
        player.sendTitle(title);
    }

    TitleSettings titleSettings(String key, long defaultDelayMillis, int defaultRepeatIntervalSeconds, boolean defaultRepeat) {
        String path = "titles." + key + ".";
        return new TitleSettings(
                configuration.getBoolean(path + "enabled", true),
                configuration.getInt(path + "fadeIn", 10),
                configuration.getInt(path + "stay", 40),
                configuration.getInt(path + "fadeOut", 10),
                configuration.getLong(path + "delayMillis", defaultDelayMillis),
                configuration.getInt(path + "repeatIntervalSeconds", defaultRepeatIntervalSeconds),
                configuration.getBoolean(path + "repeat", defaultRepeat),
                configuration.getBoolean(path + "resetBeforeSend", false)
        );
    }

    String render(String path, Map<String, String> placeholders) {
        String configured = configuration.getString(path);
        return applyPlaceholders(configured == null ? "" : configured, placeholders);
    }

    BaseComponent[] components(String text) {
        return TextComponent.fromLegacyText(color(text));
    }

    private String applyPlaceholders(String text, Map<String, String> placeholders) {
        Map<String, String> merged = new LinkedHashMap<>();
        merged.put("%prefix%", configuration.getString("prefix", ""));
        merged.putAll(placeholders);

        String applied = text;
        for (Map.Entry<String, String> entry : merged.entrySet()) {
            applied = applied.replace(entry.getKey(), entry.getValue() == null ? "" : entry.getValue());
        }
        return applied;
    }

    private String color(String text) {
        return ChatColor.translateAlternateColorCodes('&', text == null ? "" : text);
    }

    private String strip(String text) {
        return ChatColor.stripColor(color(text));
    }

    record TitleSettings(boolean enabled,
                         int fadeIn,
                         int stay,
                         int fadeOut,
                         long delayMillis,
                         int repeatIntervalSeconds,
                         boolean repeat,
                         boolean resetBeforeSend) {
    }
}
