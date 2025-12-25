package io.healthsamurai.keycloak.auditevent.config;

/**
 * Configuration constants for the Keycloak FHIR AuditEvent Plugin.
 * All settings can be configured via environment variables or system properties.
 */
public final class PluginConfig {

    private PluginConfig() {
        // Utility class
    }

    // ==================== Environment Variable Names ====================

    /** FHIR server base URL (e.g., http://fhir-server:8080/fhir) */
    public static final String FHIR_SERVER_URL = "FHIR_SERVER_URL";

    /** Authentication type: none, basic, bearer */
    public static final String FHIR_AUTH_TYPE = "FHIR_AUTH_TYPE";

    /** Username for Basic Auth */
    public static final String FHIR_AUTH_USERNAME = "FHIR_AUTH_USERNAME";

    /** Password for Basic Auth */
    public static final String FHIR_AUTH_PASSWORD = "FHIR_AUTH_PASSWORD";

    /** Bearer token for Bearer Auth */
    public static final String FHIR_AUTH_TOKEN = "FHIR_AUTH_TOKEN";

    /** Comma-separated list of event types to process (empty = all supported) */
    public static final String FHIR_EVENT_TYPES = "FHIR_EVENT_TYPES";

    /** Enable/disable admin events processing */
    public static final String FHIR_ADMIN_EVENTS_ENABLED = "FHIR_ADMIN_EVENTS_ENABLED";

    /** Enable/disable async event sending */
    public static final String FHIR_ASYNC_ENABLED = "FHIR_ASYNC_ENABLED";

    /** Enable/disable debug mode (logs original Keycloak events and AuditEvents) */
    public static final String FHIR_DEBUG_ENABLED = "FHIR_DEBUG_ENABLED";

    // ==================== Default Values ====================

    public static final String DEFAULT_FHIR_SERVER_URL = "http://localhost:8080/fhir";
    public static final String DEFAULT_AUTH_TYPE = "none";
    public static final boolean DEFAULT_ADMIN_EVENTS_ENABLED = false;
    public static final boolean DEFAULT_ASYNC_ENABLED = true;
    public static final boolean DEFAULT_DEBUG_ENABLED = false;

    // ==================== HTTP Configuration ====================

    public static final int CONNECTION_TIMEOUT_SECONDS = 10;
    public static final int REQUEST_TIMEOUT_SECONDS = 30;
    public static final String CONTENT_TYPE_FHIR_JSON = "application/fhir+json";

    // ==================== Auth Types ====================

    public static final String AUTH_TYPE_NONE = "none";
    public static final String AUTH_TYPE_BASIC = "basic";
    public static final String AUTH_TYPE_BEARER = "bearer";

    // ==================== Helper Methods ====================

    /**
     * Gets a configuration value from system property or environment variable.
     *
     * @param key The configuration key
     * @param defaultValue The default value if not found
     * @return The configuration value
     */
    public static String getConfig(String key, String defaultValue) {
        String value = System.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            value = System.getenv(key);
        }
        return (value != null && !value.trim().isEmpty()) ? value.trim() : defaultValue;
    }

    /**
     * Gets a boolean configuration value.
     *
     * @param key The configuration key
     * @param defaultValue The default value if not found
     * @return The configuration value as boolean
     */
    public static boolean getBooleanConfig(String key, boolean defaultValue) {
        String value = getConfig(key, null);
        if (value == null) {
            return defaultValue;
        }
        return Boolean.parseBoolean(value);
    }

    /**
     * Gets the configured FHIR server URL.
     *
     * @return The FHIR server URL
     */
    public static String getFhirServerUrl() {
        return getConfig(FHIR_SERVER_URL, DEFAULT_FHIR_SERVER_URL);
    }

    /**
     * Gets the configured authentication type.
     *
     * @return The auth type (none, basic, bearer)
     */
    public static String getAuthType() {
        return getConfig(FHIR_AUTH_TYPE, DEFAULT_AUTH_TYPE).toLowerCase();
    }

    /**
     * Checks if admin events processing is enabled.
     *
     * @return true if admin events should be processed
     */
    public static boolean isAdminEventsEnabled() {
        return getBooleanConfig(FHIR_ADMIN_EVENTS_ENABLED, DEFAULT_ADMIN_EVENTS_ENABLED);
    }

    /**
     * Checks if async sending is enabled.
     *
     * @return true if events should be sent asynchronously
     */
    public static boolean isAsyncEnabled() {
        return getBooleanConfig(FHIR_ASYNC_ENABLED, DEFAULT_ASYNC_ENABLED);
    }

    /**
     * Checks if debug mode is enabled.
     *
     * @return true if debug logging should be enabled
     */
    public static boolean isDebugEnabled() {
        return getBooleanConfig(FHIR_DEBUG_ENABLED, DEFAULT_DEBUG_ENABLED);
    }
}

