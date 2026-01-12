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

import java.lang.reflect.Method;

/**
 * Provider for obtaining bearer tokens from Keycloak using internal API (no HTTP).
 * Uses KeycloakSession and reflection to access internal token generation mechanisms.
 * 
 * This implementation attempts to use Keycloak's internal TokenService or TokenManager
 * through reflection, as these classes are not available through public SPI API.
 */
public class KeycloakInternalTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(KeycloakInternalTokenProvider.class);

    private final KeycloakSession session;
    private final String clientId;
    private final String clientSecret;
    private final String realmName;

    /**
     * Creates a new KeycloakInternalTokenProvider using KeycloakSession.
     *
     * @param session The Keycloak session
     */
    public KeycloakInternalTokenProvider(KeycloakSession session) {
        this.session = session;
        this.clientId = PluginConfig.getConfig(PluginConfig.KEYCLOAK_CLIENT_ID, "");
        this.clientSecret = PluginConfig.getConfig(PluginConfig.KEYCLOAK_CLIENT_SECRET, "");
        this.realmName = PluginConfig.getConfig(PluginConfig.KEYCLOAK_REALM, "master");

        if (clientId.isEmpty()) {
            log.warn("KeycloakInternalTokenProvider: Client ID not configured");
        } else {
            log.info("KeycloakInternalTokenProvider initialized - Client ID: {}, Realm: {}",
                    clientId, realmName);
            log.debug("KeycloakInternalTokenProvider: Using internal Keycloak API (no HTTP)");
        }
    }

    /**
     * Gets a bearer token using Keycloak internal API (no HTTP).
     * 
     * Attempts to use TokenService or TokenManager through reflection.
     *
     * @return Bearer token string (without "Bearer " prefix), or null if failed
     */
    public String getBearerToken() {
        if (clientId.isEmpty()) {
            log.warn("Cannot get token: Client ID not configured");
            return null;
        }

        try {
            log.debug("Getting bearer token using Keycloak internal API (no HTTP) for client: {}", clientId);

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

            // Try multiple approaches to get token
            
            // Approach 1: Try to get TokenService through session provider
            log.debug("Attempting Approach 1: TokenService via session.getProvider()");
            Object tokenService = getTokenService();
            if (tokenService != null) {
                log.debug("TokenService obtained, attempting to get token");
                String token = getTokenFromTokenService(tokenService, realm, client, serviceAccountUser);
                if (token != null && !token.isEmpty()) {
                    log.info("Successfully obtained token via TokenService");
                    return token;
                } else {
                    log.warn("TokenService obtained but failed to generate token");
                }
            } else {
                log.debug("Approach 1 failed: TokenService not available");
            }

            // Approach 2: Try to get TokenManager through reflection
            log.debug("Attempting Approach 2: TokenManager via reflection");
            Object tokenManager = getTokenManager();
            if (tokenManager != null) {
                log.debug("TokenManager obtained, attempting to get token");
                String token = getTokenFromTokenManager(tokenManager, realm, client, serviceAccountUser);
                if (token != null && !token.isEmpty()) {
                    log.info("Successfully obtained token via TokenManager");
                    return token;
                } else {
                    log.warn("TokenManager obtained but failed to generate token");
                }
            } else {
                log.debug("Approach 2 failed: TokenManager not available");
            }

            // Approach 3: Try to get TokenService through different provider interface
            log.debug("Attempting Approach 3: TokenService via provider factory");
            Object tokenServiceAlt = getTokenServiceAlternative();
            if (tokenServiceAlt != null) {
                log.debug("TokenService (alternative) obtained, attempting to get token");
                String token = getTokenFromTokenService(tokenServiceAlt, realm, client, serviceAccountUser);
                if (token != null && !token.isEmpty()) {
                    log.info("Successfully obtained token via TokenService (alternative)");
                    return token;
                } else {
                    log.warn("TokenService (alternative) obtained but failed to generate token");
                }
            } else {
                log.debug("Approach 3 failed: TokenService (alternative) not available");
            }

            // Approach 4: Try to use session's token manager directly
            log.debug("Attempting Approach 4: TokenManager via session method");
            String token = getTokenFromSessionManager(realm, client, serviceAccountUser);
            if (token != null && !token.isEmpty()) {
                log.info("Successfully obtained token via session token manager");
                return token;
            } else {
                log.debug("Approach 4 failed: Session token manager not available");
            }

            // Approach 5: Create token manually using Keycloak 26 native API
            log.debug("Attempting Approach 5: Create token manually using native Keycloak API");
            token = createTokenManually(realm, client, serviceAccountUser);
            if (token != null && !token.isEmpty()) {
                log.info("Successfully created token manually using native Keycloak API");
                return token;
            } else {
                log.debug("Approach 5 failed: Could not create token manually");
            }

            // All approaches failed - log detailed error
            log.error("Could not obtain bearer token using any internal Keycloak API method.");
            log.error("All 5 approaches attempted:");
            log.error("  1. TokenService via session.getProvider(org.keycloak.token.TokenService.class)");
            log.error("  2. TokenManager via new TokenManager() reflection");
            log.error("  3. TokenService via provider factory");
            log.error("  4. TokenManager via session.getTokenManager() or session.tokenManager()");
            log.error("  5. Manual token creation using native Keycloak API");
            log.error("");
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
            log.error("Exception while getting token using Keycloak internal API: {} - {}",
                    e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Full error:", e);
            }
            return null;
        }
    }

    /**
     * Attempts to get TokenService through session provider.
     */
    @SuppressWarnings("unchecked")
    private Object getTokenService() {
        try {
            // Try to get TokenService provider using reflection
            Class<?> tokenServiceClass = Class.forName("org.keycloak.token.TokenService");
            log.debug("TokenService class found: {}", tokenServiceClass.getName());
            
            // Use reflection to call getProvider with proper type
            Method getProviderMethod = session.getClass().getMethod("getProvider", Class.class);
            log.debug("getProvider method found, invoking with TokenService class");
            
            Object tokenService = getProviderMethod.invoke(session, tokenServiceClass);
            if (tokenService != null) {
                log.info("Successfully obtained TokenService provider via getProvider()");
                return tokenService;
            } else {
                log.warn("getProvider() returned null for TokenService - provider may not be registered");
            }
        } catch (ClassNotFoundException e) {
            log.warn("TokenService class not found: {}. This may indicate Keycloak version incompatibility.", e.getMessage());
            log.debug("Full ClassNotFoundException:", e);
        } catch (NoSuchMethodException e) {
            log.warn("getProvider method not found in KeycloakSession: {}", e.getMessage());
            log.debug("Available methods in KeycloakSession (sample): {}", 
                    java.util.Arrays.stream(session.getClass().getMethods())
                            .map(Method::getName)
                            .filter(name -> name.contains("Provider") || name.contains("Token"))
                            .limit(10)
                            .collect(java.util.stream.Collectors.joining(", ")));
        } catch (Exception e) {
            log.warn("Could not get TokenService provider: {} - {}", 
                    e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Full exception:", e);
            }
        }
        return null;
    }

    /**
     * Alternative method to get TokenService - tries different approaches.
     */
    @SuppressWarnings("unchecked")
    private Object getTokenServiceAlternative() {
        try {
            // Try to get provider by name
            Class<?> providerFactoryClass = Class.forName("org.keycloak.provider.ProviderFactory");
            Method getProviderFactoryMethod = session.getClass().getMethod("getProviderFactory", Class.class);
            
            Class<?> tokenServiceClass = Class.forName("org.keycloak.token.TokenService");
            Object factory = getProviderFactoryMethod.invoke(session, tokenServiceClass);
            if (factory != null) {
                log.debug("Found TokenService factory");
                // Try to get provider instance from factory
                Method createMethod = factory.getClass().getMethod("create", KeycloakSession.class);
                Object tokenService = createMethod.invoke(factory, session);
                if (tokenService != null) {
                    log.debug("Created TokenService instance from factory");
                    return tokenService;
                }
            }
        } catch (ClassNotFoundException e) {
            log.debug("TokenService class not found in alternative method: {}", e.getMessage());
        } catch (NoSuchMethodException e) {
            log.debug("Method not found in alternative approach: {}", e.getMessage());
        } catch (Exception e) {
            log.debug("Alternative TokenService access failed: {} - {}", 
                    e.getClass().getSimpleName(), e.getMessage());
        }
        return null;
    }

    /**
     * Tries to get token using session's internal token manager.
     */
    private String getTokenFromSessionManager(RealmModel realm, ClientModel client, UserModel serviceAccountUser) {
        try {
            // Try to access session's token manager through reflection
            // Some Keycloak versions expose token manager through session
            Method getTokenManagerMethod = null;
            try {
                getTokenManagerMethod = session.getClass().getMethod("getTokenManager");
            } catch (NoSuchMethodException e) {
                try {
                    getTokenManagerMethod = session.getClass().getMethod("tokenManager");
                } catch (NoSuchMethodException e2) {
                    log.debug("No tokenManager method found in session");
                }
            }

            if (getTokenManagerMethod != null) {
                Object tokenManager = getTokenManagerMethod.invoke(session);
                if (tokenManager != null) {
                    log.debug("Found token manager through session method");
                    return getTokenFromTokenManager(tokenManager, realm, client, serviceAccountUser);
                }
            }
        } catch (Exception e) {
            log.debug("Could not get token from session manager: {} - {}", 
                    e.getClass().getSimpleName(), e.getMessage());
        }
        return null;
    }

    /**
     * Attempts to get TokenManager through reflection.
     */
    private Object getTokenManager() {
        try {
            // Try to instantiate TokenManager
            Class<?> tokenManagerClass = Class.forName("org.keycloak.services.managers.TokenManager");
            log.debug("TokenManager class found: {}", tokenManagerClass.getName());
            
            // Try default constructor first
            try {
                java.lang.reflect.Constructor<?> defaultConstructor = tokenManagerClass.getDeclaredConstructor();
                defaultConstructor.setAccessible(true); // Make private constructor accessible
                Object tokenManager = defaultConstructor.newInstance();
                log.info("Successfully created TokenManager instance via reflection (default constructor)");
                return tokenManager;
            } catch (NoSuchMethodException e) {
                log.debug("TokenManager default constructor not found, trying with KeycloakSession parameter");
                // Try constructor with KeycloakSession parameter
                try {
                    java.lang.reflect.Constructor<?> constructor = tokenManagerClass.getDeclaredConstructor(KeycloakSession.class);
                    constructor.setAccessible(true);
                    Object tokenManager = constructor.newInstance(session);
                    log.info("Successfully created TokenManager instance with session parameter");
                    return tokenManager;
                } catch (NoSuchMethodException e2) {
                    log.warn("TokenManager has no accessible constructor (tried default and KeycloakSession)");
                    // List available constructors for debugging
                    log.debug("Available TokenManager constructors: {}", 
                            java.util.Arrays.stream(tokenManagerClass.getDeclaredConstructors())
                                    .map(c -> java.util.Arrays.toString(c.getParameterTypes()))
                                    .collect(java.util.stream.Collectors.joining(", ")));
                }
            }
        } catch (ClassNotFoundException e) {
            log.warn("TokenManager class not found: {}. This may indicate Keycloak version incompatibility.", e.getMessage());
            log.debug("Full ClassNotFoundException:", e);
        } catch (Exception e) {
            log.warn("Could not create TokenManager: {} - {}", 
                    e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Full exception:", e);
            }
        }
        return null;
    }

    /**
     * Gets token from TokenService using reflection.
     */
    private String getTokenFromTokenService(Object tokenService, RealmModel realm, 
                                           ClientModel client, UserModel serviceAccountUser) {
        try {
            // Create user session
            UserSessionModel userSession = session.sessions().createUserSession(
                    realm, serviceAccountUser, serviceAccountUser.getUsername(),
                    "127.0.0.1", "internal", false, null, null);

            if (userSession == null) {
                log.error("Failed to create user session");
                return null;
            }

            // Create client session
            AuthenticatedClientSessionModel clientSession = session.sessions()
                    .createClientSession(realm, client, userSession);
            
            if (clientSession == null) {
                log.error("Failed to create client session");
                return null;
            }

            // Create client session context
            org.keycloak.models.ClientSessionContext clientSessionCtx = DefaultClientSessionContext
                    .fromClientSessionScopeParameter(clientSession, session);

            // Try to call grantToken or createClientAccessToken method
            Method grantTokenMethod = null;
            try {
                grantTokenMethod = tokenService.getClass().getMethod("grantToken",
                        RealmModel.class, ClientModel.class, UserModel.class, 
                        UserModel.class, org.keycloak.models.ClientSessionContext.class, KeycloakSession.class);
            } catch (NoSuchMethodException e) {
                try {
                    grantTokenMethod = tokenService.getClass().getMethod("createClientAccessToken",
                            KeycloakSession.class, RealmModel.class, ClientModel.class, 
                            UserModel.class, UserSessionModel.class, org.keycloak.models.ClientSessionContext.class);
                } catch (NoSuchMethodException e2) {
                    log.debug("Could not find grantToken or createClientAccessToken method");
                }
            }

            if (grantTokenMethod != null) {
                Object result = grantTokenMethod.invoke(tokenService, 
                        realm, client, serviceAccountUser, serviceAccountUser, clientSessionCtx, session);
                if (result instanceof String) {
                    return (String) result;
                } else if (result instanceof AccessToken) {
                    // Need to encode token
                    return encodeToken((AccessToken) result, realm);
                }
            }

        } catch (Exception e) {
            log.debug("Failed to get token from TokenService: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Gets token from TokenManager using reflection.
     */
    private String getTokenFromTokenManager(Object tokenManager, RealmModel realm,
                                           ClientModel client, UserModel serviceAccountUser) {
        try {
            // Create user session
            UserSessionModel userSession = session.sessions().createUserSession(
                    realm, serviceAccountUser, serviceAccountUser.getUsername(),
                    "127.0.0.1", "internal", false, null, null);

            if (userSession == null) {
                return null;
            }

            // Create client session
            AuthenticatedClientSessionModel clientSession = session.sessions()
                    .createClientSession(realm, client, userSession);
            
            if (clientSession == null) {
                return null;
            }

            // Create client session context
            org.keycloak.models.ClientSessionContext clientSessionCtx = DefaultClientSessionContext
                    .fromClientSessionScopeParameter(clientSession, session);

            // Try to call createClientAccessToken method
            Method createTokenMethod = tokenManager.getClass().getMethod("createClientAccessToken",
                    KeycloakSession.class, RealmModel.class, ClientModel.class, 
                    UserModel.class, UserSessionModel.class, org.keycloak.models.ClientSessionContext.class);

            AccessToken accessToken = (AccessToken) createTokenMethod.invoke(tokenManager,
                    session, realm, client, serviceAccountUser, userSession, clientSessionCtx);

            if (accessToken != null) {
                // Try to encode token
                Method encodeMethod = tokenManager.getClass().getMethod("encodeToken",
                        KeycloakSession.class, RealmModel.class, AccessToken.class, boolean.class);
                String tokenString = (String) encodeMethod.invoke(tokenManager, session, realm, accessToken, false);
                if (tokenString != null && !tokenString.isEmpty()) {
                    log.debug("Successfully obtained token using TokenManager (token length: {})", tokenString.length());
                    return tokenString;
                }
            }

        } catch (Exception e) {
            log.debug("Failed to get token from TokenManager: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Encodes AccessToken to string using TokenManager.
     */
    private String encodeToken(AccessToken token, RealmModel realm) {
        try {
            Object tokenManager = getTokenManager();
            if (tokenManager != null) {
                Method encodeMethod = tokenManager.getClass().getMethod("encodeToken",
                        KeycloakSession.class, RealmModel.class, AccessToken.class, boolean.class);
                return (String) encodeMethod.invoke(tokenManager, session, realm, token, false);
            }
        } catch (Exception e) {
            log.debug("Failed to encode token: {}", e.getMessage());
        }
        return null;
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
