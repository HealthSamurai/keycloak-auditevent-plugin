package io.healthsamurai.keycloak.auditevent.config;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class PluginConfigTest {

    @Test
    void getConfig_NonExistentKey_ReturnsDefault() {
        String result = PluginConfig.getConfig("NON_EXISTENT_KEY_12345_RANDOM", "default-value");
        assertEquals("default-value", result);
    }

    @Test
    void getConfig_NullDefault_ReturnsNull() {
        String result = PluginConfig.getConfig("NON_EXISTENT_KEY_12345_RANDOM", null);
        assertNull(result);
    }

    @Test
    void getBooleanConfig_NonExistentKey_ReturnsDefaultTrue() {
        boolean result = PluginConfig.getBooleanConfig("NON_EXISTENT_KEY_12345_RANDOM", true);
        assertTrue(result);
    }

    @Test
    void getBooleanConfig_NonExistentKey_ReturnsDefaultFalse() {
        boolean result = PluginConfig.getBooleanConfig("NON_EXISTENT_KEY_12345_RANDOM", false);
        assertFalse(result);
    }

    @Test
    void getFhirServerUrl_ReturnsDefaultWhenNotSet() {
        String url = PluginConfig.getFhirServerUrl();
        assertNotNull(url);
        assertFalse(url.isEmpty());
        // Default URL should contain localhost or be the configured value
        assertTrue(url.contains("localhost") || url.contains("http"));
    }

    @Test
    void getAuthType_ReturnsDefaultWhenNotSet() {
        String authType = PluginConfig.getAuthType();
        assertEquals("none", authType);
    }

    @Test
    void isAdminEventsEnabled_DefaultFalse() {
        boolean enabled = PluginConfig.isAdminEventsEnabled();
        assertFalse(enabled);
    }

    @Test
    void isAsyncEnabled_DefaultTrue() {
        boolean enabled = PluginConfig.isAsyncEnabled();
        assertTrue(enabled);
    }

    @Test
    void isDebugEnabled_DefaultFalse() {
        boolean enabled = PluginConfig.isDebugEnabled();
        assertFalse(enabled);
    }

    @Test
    void constants_EnvironmentVariableNames() {
        assertEquals("FHIR_SERVER_URL", PluginConfig.FHIR_SERVER_URL);
        assertEquals("FHIR_AUTH_TYPE", PluginConfig.FHIR_AUTH_TYPE);
        assertEquals("FHIR_AUTH_USERNAME", PluginConfig.FHIR_AUTH_USERNAME);
        assertEquals("FHIR_AUTH_PASSWORD", PluginConfig.FHIR_AUTH_PASSWORD);
        assertEquals("FHIR_AUTH_TOKEN", PluginConfig.FHIR_AUTH_TOKEN);
        assertEquals("FHIR_ADMIN_EVENTS_ENABLED", PluginConfig.FHIR_ADMIN_EVENTS_ENABLED);
        assertEquals("FHIR_ASYNC_ENABLED", PluginConfig.FHIR_ASYNC_ENABLED);
        assertEquals("FHIR_DEBUG_ENABLED", PluginConfig.FHIR_DEBUG_ENABLED);
    }

    @Test
    void constants_AuthTypes() {
        assertEquals("none", PluginConfig.AUTH_TYPE_NONE);
        assertEquals("basic", PluginConfig.AUTH_TYPE_BASIC);
        assertEquals("bearer", PluginConfig.AUTH_TYPE_BEARER);
    }

    @Test
    void constants_HttpConfiguration() {
        assertEquals(10, PluginConfig.CONNECTION_TIMEOUT_SECONDS);
        assertEquals(30, PluginConfig.REQUEST_TIMEOUT_SECONDS);
        assertEquals("application/fhir+json", PluginConfig.CONTENT_TYPE_FHIR_JSON);
    }

    @Test
    void constants_DefaultValues() {
        assertEquals("http://localhost:8080/fhir", PluginConfig.DEFAULT_FHIR_SERVER_URL);
        assertEquals("none", PluginConfig.DEFAULT_AUTH_TYPE);
        assertFalse(PluginConfig.DEFAULT_ADMIN_EVENTS_ENABLED);
        assertTrue(PluginConfig.DEFAULT_ASYNC_ENABLED);
        assertFalse(PluginConfig.DEFAULT_DEBUG_ENABLED);
    }
}
