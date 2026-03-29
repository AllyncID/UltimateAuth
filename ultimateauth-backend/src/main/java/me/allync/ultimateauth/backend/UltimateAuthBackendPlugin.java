package me.allync.ultimateauth.backend;

import org.bukkit.GameMode;
import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.plugin.messaging.PluginMessageListener;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class UltimateAuthBackendPlugin extends JavaPlugin implements Listener, PluginMessageListener {
    private final Map<UUID, Boolean> frozenStates = new ConcurrentHashMap<>();

    private String accessToken;
    private String pluginChannel;
    private int blindnessAmplifier;
    private boolean skipCreative;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        reloadConfiguration();

        getServer().getPluginManager().registerEvents(this, this);
        getServer().getMessenger().registerIncomingPluginChannel(this, pluginChannel, this);
        getLogger().info("UltimateAuth backend module enabled.");
    }

    @Override
    public void onDisable() {
        getServer().getMessenger().unregisterIncomingPluginChannel(this, pluginChannel);
        for (Player player : getServer().getOnlinePlayers()) {
            clearFrozenState(player);
        }
        frozenStates.clear();
    }

    @Override
    public void onPluginMessageReceived(String channel, Player player, byte[] message) {
        if (!pluginChannel.equalsIgnoreCase(channel)) {
            return;
        }

        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(message))) {
            String token = input.readUTF();
            if (!accessToken.equals(token)) {
                return;
            }

            UUID uniqueId = UUID.fromString(input.readUTF());
            boolean frozen = input.readBoolean();
            frozenStates.put(uniqueId, frozen);

            Player target = getServer().getPlayer(uniqueId);
            if (target != null) {
                if (frozen) {
                    applyFrozenState(target);
                } else {
                    clearFrozenState(target);
                }
            }
        } catch (IOException | IllegalArgumentException exception) {
            getLogger().warning("Unable to read UltimateAuth bridge message: " + exception.getMessage());
        }
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        if (isFrozen(event.getPlayer())) {
            applyFrozenState(event.getPlayer());
        } else {
            clearFrozenState(event.getPlayer());
        }
    }

    @EventHandler
    public void onMove(PlayerMoveEvent event) {
        if (!isFrozen(event.getPlayer()) || event.getTo() == null) {
            return;
        }

        Location locked = event.getFrom().clone();
        locked.setYaw(event.getTo().getYaw());
        locked.setPitch(event.getTo().getPitch());
        event.setTo(locked);
    }

    @EventHandler
    public void onInteract(PlayerInteractEvent event) {
        if (isFrozen(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onBreak(BlockBreakEvent event) {
        if (isFrozen(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onPlace(BlockPlaceEvent event) {
        if (isFrozen(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onDrop(PlayerDropItemEvent event) {
        if (isFrozen(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onDamage(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player attacker && isFrozen(attacker)) {
            event.setCancelled(true);
            return;
        }
        if (event.getEntity() instanceof Player victim && isFrozen(victim)) {
            event.setCancelled(true);
        }
    }

    private void reloadConfiguration() {
        reloadConfig();
        accessToken = getConfig().getString("bridge.accessToken", "change-this-random-token");
        pluginChannel = getConfig().getString("bridge.pluginChannel", "ultimateauth:state");
        blindnessAmplifier = Math.max(0, getConfig().getInt("freeze.blindnessAmplifier", 0));
        skipCreative = getConfig().getBoolean("freeze.skipCreative", true);
    }

    private boolean isFrozen(Player player) {
        return frozenStates.getOrDefault(player.getUniqueId(), false) && !shouldSkipPlayer(player);
    }

    private boolean shouldSkipPlayer(Player player) {
        return skipCreative && (player.getGameMode() == GameMode.CREATIVE || player.getGameMode() == GameMode.SPECTATOR);
    }

    private void applyFrozenState(Player player) {
        if (shouldSkipPlayer(player)) {
            clearFrozenState(player);
            return;
        }

        player.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, Integer.MAX_VALUE, blindnessAmplifier, false, false, false), true);
    }

    private void clearFrozenState(Player player) {
        player.removePotionEffect(PotionEffectType.BLINDNESS);
    }
}
