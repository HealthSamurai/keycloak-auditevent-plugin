package io.healthsamurai.keycloak.auditevent.client;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.healthsamurai.keycloak.auditevent.config.PluginConfig;
import io.healthsamurai.keycloak.auditevent.util.JsonUtil;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.keycloak.models.KeycloakSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP client for sending FHIR R4 AuditEvent resources to a FHIR server.
 * Supports multiple authentication methods: none, Basic Auth, Bearer Token.
 */
public class FhirClient {

    private static final Logger log = LoggerFactory.getLogger(FhirClient.class);

    private final String fhirServerUrl;
    private final String authType;
    private final String authHeader;
    private final KeycloakInternalTokenProvider internalTokenProvider;
    private final HttpClient httpClient;
    private final ExecutorService executor;
    private final boolean asyncEnabled;

    /**
     * Creates a new FhirClient with configuration from environment/system properties.
     */
    public FhirClient() {
        this(null);
    }

    /**
     * Creates a new FhirClient with KeycloakSession for internal token provider.
     *
     * @param session The Keycloak session (can be null)
     */
    public FhirClient(KeycloakSession session) {
        this.fhirServerUrl = PluginConfig.getFhirServerUrl();
        this.authType = PluginConfig.getAuthType();
        this.asyncEnabled = PluginConfig.isAsyncEnabled();

        // Initialize internal token provider if using keycloak auth and session is available
        if (PluginConfig.AUTH_TYPE_KEYCLOAK.equals(authType) && session != null) {
            log.debug("Initializing KeycloakInternalTokenProvider for internal API token retrieval");
            this.internalTokenProvider = new KeycloakInternalTokenProvider(session);
            this.authHeader = null; // Will be obtained dynamically
        } else {
            this.internalTokenProvider = null;
            this.authHeader = buildAuthHeader();
        }

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(PluginConfig.CONNECTION_TIMEOUT_SECONDS))
                .build();

        this.executor = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "fhir-client-worker");
            t.setDaemon(true);
            return t;
        });

        log.info("FhirClient initialized - URL: {}, Auth: {}, Async: {}",
                fhirServerUrl, authType, asyncEnabled);
        if (PluginConfig.AUTH_TYPE_KEYCLOAK.equals(authType) && session != null) {
            log.debug("FhirClient: Using Keycloak internal API for token retrieval (no HTTP)");
        }
    }

    /**
     * Constructor for testing with custom HttpClient.
     */
    public FhirClient(HttpClient httpClient, String fhirServerUrl, String authType, String authHeader) {
        this.httpClient = httpClient;
        this.fhirServerUrl = fhirServerUrl;
        this.authType = authType;
        this.authHeader = authHeader;
        this.internalTokenProvider = null;
        this.asyncEnabled = false;
        this.executor = Executors.newSingleThreadExecutor();
    }

    /**
     * Sends an AuditEvent to the FHIR server.
     * If async is enabled, sends in background and returns immediately.
     *
     * @param auditEvent The FHIR AuditEvent to send
     */
    public void sendAuditEvent(ObjectNode auditEvent) {
        if (auditEvent == null) {
            log.warn("Received null AuditEvent, skipping");
            return;
        }

        if (asyncEnabled) {
            CompletableFuture.runAsync(() -> doSendAuditEvent(auditEvent), executor)
                    .exceptionally(ex -> {
                        log.error("Async send failed: {}", ex.getMessage());
                        return null;
                    });
        } else {
            doSendAuditEvent(auditEvent);
        }
    }

    /**
     * Sends an AuditEvent synchronously.
     *
     * @param auditEvent The FHIR AuditEvent to send
     * @throws Exception if the request fails
     */
    public void sendAuditEventSync(ObjectNode auditEvent) throws Exception {
        doSendAuditEvent(auditEvent);
    }

    private void doSendAuditEvent(ObjectNode auditEvent) {
        // Use URL as-is (don't append /AuditEvent - user configures full endpoint)
        String url = fhirServerUrl.endsWith("/")
                ? fhirServerUrl.substring(0, fhirServerUrl.length() - 1)
                : fhirServerUrl;

        try {
            String jsonBody = JsonUtil.toJson(auditEvent);
            log.debug("Sending AuditEvent to {}: {}", url, jsonBody);

            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", PluginConfig.CONTENT_TYPE_FHIR_JSON)
                    .header("Accept", PluginConfig.CONTENT_TYPE_FHIR_JSON)
                    .timeout(Duration.ofSeconds(PluginConfig.REQUEST_TIMEOUT_SECONDS))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));

            // Add auth header if configured
            String authHeaderToUse = getAuthHeader();
            if (authHeaderToUse != null && !authHeaderToUse.isEmpty()) {
                requestBuilder.header("Authorization", authHeaderToUse);
            }

            HttpRequest request = requestBuilder.build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            int statusCode = response.statusCode();
            String responseBody = response.body();

            if (statusCode >= 200 && statusCode < 300) {
                log.info("AuditEvent sent successfully. Status: {}", statusCode);
                log.debug("Response: {}", responseBody);
            } else {
                log.error("FHIR server returned error. Status: {}, Body: {}", statusCode, responseBody);
            }

        } catch (Exception e) {
            log.error("Failed to send AuditEvent to FHIR server: {} - {}",
                    e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Full error:", e);
            }
        }
    }

    /**
     * Gets the authorization header for the current request.
     * For keycloak auth type, dynamically fetches token from internal provider.
     */
    private String getAuthHeader() {
        if (PluginConfig.AUTH_TYPE_KEYCLOAK.equals(authType)) {
            // Dynamically get token from internal provider
            if (internalTokenProvider != null) {
                log.debug("Requesting bearer token from KeycloakInternalTokenProvider");
                String token = internalTokenProvider.getBearerToken();
                if (token != null && !token.isEmpty()) {
                    log.debug("Successfully obtained bearer token (length: {})", token.length());
                    return "Bearer " + token;
                }
                log.warn("Keycloak auth configured but failed to obtain token");
                return null;
            }
            log.warn("Keycloak auth configured but token provider not initialized");
            return null;
        }
        // For static auth types, use cached header
        return authHeader;
    }

    private String buildAuthHeader() {
        switch (authType) {
            case PluginConfig.AUTH_TYPE_BASIC -> {
                String username = PluginConfig.getConfig(PluginConfig.FHIR_AUTH_USERNAME, "");
                String password = PluginConfig.getConfig(PluginConfig.FHIR_AUTH_PASSWORD, "");
                if (!username.isEmpty()) {
                    String credentials = username + ":" + password;
                    String encoded = Base64.getEncoder()
                            .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
                    return "Basic " + encoded;
                }
                log.warn("Basic auth configured but no username provided");
                return null;
            }
            case PluginConfig.AUTH_TYPE_BEARER -> {
                String token = PluginConfig.getConfig(PluginConfig.FHIR_AUTH_TOKEN, "");
                if (!token.isEmpty()) {
                    return "Bearer " + token;
                }
                log.warn("Bearer auth configured but no token provided");
                return null;
            }
            default -> {
                return null;
            }
        }
    }

    /**
     * Closes the client and releases resources.
     */
    public void close() {
        if (executor != null && !executor.isShutdown()) {
            executor.shutdown();
        }
    }

    /**
     * Gets the configured FHIR server URL.
     */
    public String getFhirServerUrl() {
        return fhirServerUrl;
    }
}

