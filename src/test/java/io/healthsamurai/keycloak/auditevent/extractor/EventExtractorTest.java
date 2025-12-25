package io.healthsamurai.keycloak.auditevent.extractor;

import static org.junit.jupiter.api.Assertions.*;

import io.healthsamurai.keycloak.auditevent.model.NormalizedEvent;
import io.healthsamurai.keycloak.auditevent.builder.EventMappingLoader;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;

/**
 * Tests for EventExtractor.
 * Tests event extraction, username resolution, and admin events.
 */
class EventExtractorTest {

    private EventExtractor extractor;

    @BeforeEach
    void setUp() {
        extractor = new EventExtractor();
    }

    @Test
    void extractUserEvent_NullEvent_ReturnsNull() {
        NormalizedEvent result = extractor.extractUserEvent(null);
        assertNull(result);
    }

    @Test
    void extractAdminEvent_NullEvent_ReturnsNull() {
        NormalizedEvent result = extractor.extractAdminEvent(null);
        assertNull(result);
    }

    @Test
    void isSupported_EventsFromYaml_AreSupported() {
        Set<String> yamlEvents = EventMappingLoader.loadSupportedEventTypes();
        assertFalse(yamlEvents.isEmpty(), "YAML events should not be empty");

        for (String event : yamlEvents) {
            assertTrue(extractor.isSupported(event), "Event " + event + " from YAML should be supported");
        }
    }

    @Test
    void isSupported_UnsupportedEvent_ReturnsFalse() {
        assertFalse(extractor.isSupported("UNKNOWN_EVENT"));
        assertFalse(extractor.isSupported("IDENTITY_PROVIDER_LOGIN"));
        assertFalse(extractor.isSupported(""));
    }

    @Test
    void isSupported_NullEvent_ReturnsFalse() {
        assertFalse(extractor.isSupported(null));
    }

    @Test
    void isSupported_AllEventsFromYaml_AreSupported() {
        Set<String> yamlEvents = EventMappingLoader.loadSupportedEventTypes();

        for (String event : yamlEvents) {
            assertTrue(extractor.isSupported(event), "Event " + event + " should be supported");
        }
    }

    // Note: Keycloak Event, AdminEvent, and KeycloakSession classes cannot be mocked in Java 25
    // We test the extractUsername logic via reflection to test the private method directly
    // Full extraction tests would require integration testing with real Keycloak instances

    @Test
    void extractUsername_WithUsernameInDetails_UsesDetails() {
        Map<String, String> details = new HashMap<>();
        details.put("username", "john.doe@example.com");
        
        String username = extractUsernameViaReflection(details, "user-123", "test-realm", null);
        
        assertEquals("john.doe@example.com", username);
    }

    @Test
    void extractUsername_WithEmailInDetails_UsesEmailAsFallback() {
        Map<String, String> details = new HashMap<>();
        details.put("email", "user@example.com");
        
        String username = extractUsernameViaReflection(details, null, "test-realm", null);
        
        assertEquals("user@example.com", username);
    }

    @Test
    void extractUsername_WithNoDetails_UsesUnknown() {
        Map<String, String> details = new HashMap<>();
        
        String username = extractUsernameViaReflection(details, null, "test-realm", null);
        
        assertEquals("unknown", username);
    }

    @Test
    void extractUsername_WithUserIdButNoSession_UsesUserId() {
        Map<String, String> details = new HashMap<>();
        
        String username = extractUsernameViaReflection(details, "user-123", "test-realm", null);
        
        assertEquals("user-123", username);
    }

    @Test
    void extractUsername_WithEmptyUsernameInDetails_FallsBackToUserId() {
        Map<String, String> details = new HashMap<>();
        details.put("username", "");
        
        String username = extractUsernameViaReflection(details, "user-123", "test-realm", null);
        
        assertEquals("user-123", username);
    }

    @Test
    void extractUsername_WithUnknownUsernameInDetails_ReturnsUnknown() {
        Map<String, String> details = new HashMap<>();
        details.put("username", "unknown");
        
        String username = extractUsernameViaReflection(details, "user-123", "test-realm", null);
        
        // When username is "unknown" in details, it's returned as-is (not filtered)
        assertEquals("unknown", username);
    }

    @Test
    void extractUsername_WithNullUsernameInDetails_FallsBackToUserId() {
        Map<String, String> details = new HashMap<>();
        details.put("username", null);
        
        String username = extractUsernameViaReflection(details, "user-123", "test-realm", null);
        
        // Null username should fallback to userId
        assertEquals("user-123", username);
    }

    @Test
    void extractUsername_WithValidUsernameAndUserId_UsesUsername() {
        Map<String, String> details = new HashMap<>();
        details.put("username", "john.doe@example.com");
        
        String username = extractUsernameViaReflection(details, "user-123", "test-realm", null);
        
        // Valid username should be used even if userId is present
        assertEquals("john.doe@example.com", username);
    }

    @Test
    void extractUsername_WithEmailButNoUserId_UsesEmail() {
        Map<String, String> details = new HashMap<>();
        details.put("email", "user@example.com");
        
        String username = extractUsernameViaReflection(details, null, "test-realm", null);
        
        assertEquals("user@example.com", username);
    }

    @Test
    void extractUsername_WithEmptyEmail_UsesUnknown() {
        Map<String, String> details = new HashMap<>();
        details.put("email", "");
        
        String username = extractUsernameViaReflection(details, null, "test-realm", null);
        
        assertEquals("unknown", username);
    }

    /**
     * Helper method to test extractUsername logic via reflection.
     * Since extractUsername is private, we use reflection to access it for testing purposes.
     */
    private String extractUsernameViaReflection(Map<String, String> details, String userId, String realmId, KeycloakSession session) {
        try {
            java.lang.reflect.Method method = EventExtractor.class.getDeclaredMethod(
                    "extractUsername", Map.class, String.class, String.class, KeycloakSession.class);
            method.setAccessible(true);
            return (String) method.invoke(extractor, details, userId, realmId, session);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke extractUsername via reflection", e);
        }
    }

}
