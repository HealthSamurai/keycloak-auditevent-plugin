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
import org.keycloak.models.ClientSessionContext;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provider for obtaining bearer tokens from Keycloak using internal API (no HTTP).
 * Uses KeycloakSession and TokenManager to create and sign tokens using native Keycloak 26 API.
 *
 * This implementation uses Keycloak's TokenManager for proper token generation with all required claims.
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
     * Creates and signs JWT token using TokenManager with all proper claims.
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

            // Create token using TokenManager (proper Keycloak way)
            String token = createTokenViaTokenManager(realm, client, serviceAccountUser);
            if (token != null && !token.isEmpty()) {
                log.info("Successfully created token using TokenManager");
                return token;
            }

            // Token creation failed
            log.error("Could not create bearer token using TokenManager");
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
     * Creates a token using Keycloak's TokenManager.
     * This is the proper way to create tokens - TokenManager handles all claims,
     * token mappers, scopes, and signing automatically.
     */
    private String createTokenViaTokenManager(
            RealmModel realm,
            ClientModel client,
            UserModel serviceAccountUser
    ) {
        try {
            log.debug("Creating token via TokenManager for service account user: {}", serviceAccountUser.getUsername());

            // 1. Create user session for service account
            UserSessionModel userSession = session.sessions().createUserSession(
                    realm,
                    serviceAccountUser,
                    serviceAccountUser.getUsername(),
                    "internal",
                    "service-account",
                    false,
                    null,
                    null
            );

            if (userSession == null) {
                log.error("Failed to create user session for service account");
                return null;
            }

            log.debug("Created user session: {}", userSession.getId());

            // 2. Create authenticated client session
            AuthenticatedClientSessionModel clientSession =
                    session.sessions().createClientSession(realm, client, userSession);

            if (clientSession == null) {
                log.error("Failed to create client session");
                return null;
            }

            // Set protocol to OIDC (important for token generation)
            clientSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);

            log.debug("Created client session for client: {}", client.getClientId());

            // 3. Create ClientSessionContext (ВАЖНО - содержит scopes и mappers)
            ClientSessionContext clientSessionCtx =
                    DefaultClientSessionContext.fromClientSessionScopeParameter(
                            clientSession, session
                    );

            // 4. Set realm and client in session context (required for TokenManager)
            session.getContext().setRealm(realm);
            session.getContext().setClient(client);

            // 5. Use TokenManager to create proper AccessToken with all claims
            TokenManager tokenManager = new TokenManager();

            AccessToken accessToken = tokenManager.createClientAccessToken(
                    session,
                    realm,
                    client,
                    serviceAccountUser,
                    userSession,
                    clientSessionCtx
            );

            if (accessToken == null) {
                log.error("TokenManager returned null AccessToken");
                return null;
            }

            log.debug("AccessToken created with ID: {}, Subject: {}, Issuer: {}",
                    accessToken.getId(), accessToken.getSubject(), accessToken.getIssuer());

            // 6. Sign and serialize token using session.tokens().encode()
            // This automatically adds kid to JWT header and uses proper signing
            String tokenString = session.tokens().encode(accessToken);

            if (tokenString == null || tokenString.isEmpty()) {
                log.error("Failed to encode token - session.tokens().encode() returned null");
                return null;
            }

            log.info("Successfully created and signed token via TokenManager (length: {})", tokenString.length());
            log.debug("Token issuer: {}", accessToken.getIssuer());
            log.debug("Token expires at: {}", new java.util.Date(accessToken.getExp() * 1000L));

            // Log first and last 20 chars of token for debugging (don't log full token in production)
            if (log.isDebugEnabled() && tokenString.length() > 40) {
                String tokenPreview = tokenString.substring(0, 20) + "..." + tokenString.substring(tokenString.length() - 20);
                log.debug("Token preview: {}", tokenPreview);
            }

            return tokenString;
        } catch (Exception e) {
            log.error("Failed to create token via TokenManager: {} - {}",
                    e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Full exception:", e);
            }
            return null;
        }
    }
}
