package io.healthsamurai.keycloak.auditevent.client;

import io.healthsamurai.keycloak.auditevent.config.PluginConfig;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.representations.AccessToken;
import org.keycloak.common.util.Time;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.ClientSessionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provider for obtaining bearer tokens from Keycloak using internal API (no HTTP).
 * Uses KeycloakSession to create and sign tokens using native Keycloak 26 API.
 *
 * This implementation directly creates AccessToken and signs it using the realm's RSA key.
 */
public class KeycloakInternalTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(KeycloakInternalTokenProvider.class);

    private final KeycloakSession session;
    private final String clientId;
    private final String realmName;

    /**
     * Creates a new KeycloakInternalTokenProvider using KeycloakSession.
     *
     * @param session The Keycloak session
     */
    public KeycloakInternalTokenProvider(KeycloakSession session) {
        this.session = session;
        this.clientId = PluginConfig.getConfig(PluginConfig.KEYCLOAK_CLIENT_ID, "");
        this.realmName = PluginConfig.getConfig(PluginConfig.KEYCLOAK_REALM, "master");

        if (clientId.isEmpty()) {
            log.warn("KeycloakInternalTokenProvider: Client ID not configured");
        } else {
            log.info("KeycloakInternalTokenProvider initialized - Client ID: {}, Realm: {}",
                    clientId, realmName);
            log.debug("KeycloakInternalTokenProvider: Using native Keycloak 26 API (no HTTP, no reflection)");
        }
    }

    /**
     * Gets a bearer token using Keycloak native API (no HTTP, no reflection).
     * Creates and signs JWT token directly using realm's RSA key.
     *
     * @return Bearer token string (without "Bearer " prefix), or null if failed
     */
    public String getBearerToken() {
        if (clientId.isEmpty()) {
            log.warn("Cannot get token: Client ID not configured");
            return null;
        }

        try {
            log.debug("Creating bearer token using native Keycloak 26 API for client: {}", clientId);

            RealmModel realm = session.realms().getRealmByName(realmName);
            if (realm == null) {
                log.error("Realm '{}' not found", realmName);
                return null;
            }

            ClientModel client = session.clients().getClientByClientId(realm, clientId);
            if (client == null) {
                log.error("Client '{}' not found in realm '{}'", clientId, realmName);
                return null;
            }

            // Check if client has service account enabled
            if (!client.isServiceAccountsEnabled()) {
                log.error("Client '{}' does not have service accounts enabled", clientId);
                return null;
            }

            // Get service account user for the client
            UserModel serviceAccountUser = session.users().getServiceAccount(client);
            if (serviceAccountUser == null) {
                log.error("Service account user not found for client '{}'", clientId);
                return null;
            }

            log.debug("Found service account user: {}", serviceAccountUser.getId());

            // Create token using native Keycloak 26 API
            String token = createTokenManually(realm, client, serviceAccountUser);
            if (token != null && !token.isEmpty()) {
                log.info("Successfully created token using native Keycloak API");
                return token;
            }

            // Token creation failed
            log.error("Could not create bearer token using native Keycloak API");
            log.error("Possible reasons:");
            log.error("  - Service account not properly configured for client '{}'", clientId);
            log.error("  - Missing permissions or roles on service account");
            log.error("  - Keycloak session context issues");
            log.error("");
            log.error("Verify:");
            log.error("  - Client '{}' has 'Service Account Enabled' in Keycloak admin console", clientId);
            log.error("  - Service account user exists and has required roles");
            log.error("  - Plugin is running within Keycloak's JVM with proper session access");

            return null;

        } catch (Exception e) {
            log.error("Exception while creating token using native Keycloak API: {} - {}",
                    e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Full error:", e);
            }
            return null;
        }
    }


    /**
     * Creates a token manually using native Keycloak 26 API.
     * This approach directly creates an AccessToken and signs it using the session's keys.
     */
    private String createTokenManually(RealmModel realm, ClientModel client, UserModel serviceAccountUser) {
        try {
            log.debug("Creating token manually for service account user: {}", serviceAccountUser.getUsername());

            // Create user session for service account
            UserSessionModel userSession = session.sessions().createUserSession(
                    realm, serviceAccountUser, serviceAccountUser.getUsername(),
                    "127.0.0.1", "service-account", false, null, null);

            if (userSession == null) {
                log.error("Failed to create user session for service account");
                return null;
            }

            log.debug("Created user session: {}", userSession.getId());

            // Create authenticated client session
            AuthenticatedClientSessionModel clientSession = session.sessions()
                    .createClientSession(realm, client, userSession);

            if (clientSession == null) {
                log.error("Failed to create client session");
                return null;
            }

            log.debug("Created client session for client: {}", client.getClientId());

            // Create client session context
            ClientSessionContext clientSessionCtx = DefaultClientSessionContext
                    .fromClientSessionScopeParameter(clientSession, session);

            // Create AccessToken
            AccessToken token = new AccessToken();
            token.id(org.keycloak.models.utils.KeycloakModelUtils.generateId());
            token.type("Bearer");
            token.subject(serviceAccountUser.getId());

            // Build issuer URL
            String issuer = session.getContext().getUri().getBaseUri().toString() + "realms/" + realm.getName();
            token.issuer(issuer);

            token.issuedNow();

            // Set expiration using exp(Long) method
            int expirationTime = Time.currentTime() + realm.getAccessTokenLifespan();
            token.exp((long) expirationTime);

            // Set azp (authorized party) - using field directly
            token.setOtherClaims("azp", client.getClientId());

            // Add audience
            token.audience(client.getClientId());

            // Add session state - using field directly
            token.setOtherClaims("session_state", userSession.getId());

            // Set allowed origins
            if (client.getRootUrl() != null) {
                token.setAllowedOrigins(java.util.Collections.singleton(client.getRootUrl()));
            }

            // Add realm access roles
            java.util.Set<String> realmRoles = new java.util.HashSet<>();
            serviceAccountUser.getRoleMappingsStream().forEach(role -> {
                if (role.getContainer().equals(realm)) {
                    realmRoles.add(role.getName());
                }
            });
            if (!realmRoles.isEmpty()) {
                token.setRealmAccess(new org.keycloak.representations.AccessToken.Access().roles(realmRoles));
            }

            log.debug("AccessToken created with ID: {}, Subject: {}", token.getId(), token.getSubject());

            // Sign the token using JWSBuilder and realm's active RS256 key
            String tokenString = new JWSBuilder()
                    .type("JWT")
                    .jsonContent(token)
                    .rsa256(session.keys().getActiveRsaKey(realm).getPrivateKey());

            if (tokenString == null || tokenString.isEmpty()) {
                log.error("Failed to sign token - JWSBuilder returned null");
                return null;
            }

            log.info("Successfully created and signed token manually (length: {})", tokenString.length());
            log.debug("Token expires at: {}", new java.util.Date(token.getExp() * 1000L));

            return tokenString;

        } catch (Exception e) {
            log.error("Failed to create token manually: {} - {}",
                    e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Full exception:", e);
            }
            return null;
        }
    }
}
