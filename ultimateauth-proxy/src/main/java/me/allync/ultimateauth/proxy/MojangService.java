package me.allync.ultimateauth.proxy;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class MojangService {
    private static final Pattern PROFILE_ID_PATTERN = Pattern.compile("\"id\"\\s*:\\s*\"([a-fA-F0-9]{32})\"");
    private static final long CACHE_TTL_MILLIS = Duration.ofMinutes(5).toMillis();
    private static final long ERROR_CACHE_TTL_MILLIS = Duration.ofSeconds(30).toMillis();

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private final ConcurrentHashMap<String, CachedProfile> cache = new ConcurrentHashMap<>();
    private final UltimateAuthPlugin plugin;

    MojangService(UltimateAuthPlugin plugin) {
        this.plugin = plugin;
    }

    Optional<PremiumProfile> lookupProfile(String playerName) {
        PremiumLookupResult result = lookupProfileResult(playerName);
        return result.found() ? Optional.of(result.profile()) : Optional.empty();
    }

    PremiumLookupResult lookupProfileResult(String playerName) {
        String key = playerName.toLowerCase(Locale.ROOT);
        CachedProfile cached = cache.get(key);
        long now = System.currentTimeMillis();
        if (cached != null && cached.expiresAt() > now) {
            return cached.result();
        }

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.mojang.com/users/profiles/minecraft/" +
                            URLEncoder.encode(playerName, StandardCharsets.UTF_8)))
                    .timeout(Duration.ofSeconds(5))
                    .header("Accept", "application/json")
                    .header("User-Agent", "UltimateAuth/1.0")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            PremiumLookupResult result = PremiumLookupResult.notFound();
            if (response.statusCode() == 200) {
                Matcher matcher = PROFILE_ID_PATTERN.matcher(response.body());
                if (matcher.find()) {
                    result = PremiumLookupResult.found(new PremiumProfile(parseMojangUuid(matcher.group(1))));
                }
            } else if (response.statusCode() != 204 && response.statusCode() != 404) {
                result = PremiumLookupResult.error();
            }
            cache.put(key, new CachedProfile(result, now + (result.status() == PremiumLookupStatus.ERROR ? ERROR_CACHE_TTL_MILLIS : CACHE_TTL_MILLIS)));
            return result;
        } catch (IOException | InterruptedException exception) {
            if (exception instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            plugin.getLogger().warning("Unable to check Mojang profile for " + playerName + ": " + exception.getMessage());
            PremiumLookupResult result = PremiumLookupResult.error();
            cache.put(key, new CachedProfile(result, now + ERROR_CACHE_TTL_MILLIS));
            return result;
        }
    }

    private UUID parseMojangUuid(String compactUuid) {
        String value = compactUuid.replaceFirst(
                "(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)",
                "$1-$2-$3-$4-$5"
        );
        return UUID.fromString(value);
    }

    private record CachedProfile(PremiumLookupResult result, long expiresAt) {
    }
}
