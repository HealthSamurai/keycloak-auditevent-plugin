package io.healthsamurai.keycloak.auditevent.builder;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.healthsamurai.keycloak.auditevent.model.NormalizedEvent;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuditEventBuilderTest {

    private AuditEventBuilder builder;

    @BeforeEach
    void setUp() {
        builder = new AuditEventBuilder();
    }

    @Test
    void buildAuditEvent_Login_Success() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("LOGIN")
                .time(1700000000000L)
                .userId("user-123")
                .username("john.doe@example.com")
                .ipAddress("192.168.1.100")
                .realmId("test-realm")
                .clientId("my-app")
                .sessionId("session-456")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        assertEquals("AuditEvent", result.get("resourceType").asText());
        assertNotNull(result.get("id"));

        // Check type
        JsonNode type = result.get("type");
        assertEquals("http://dicom.nema.org/resources/ontology/DCM", type.get("system").asText());
        assertEquals("110114", type.get("code").asText());
        assertEquals("User Authentication", type.get("display").asText());

        // Check action
        assertEquals("E", result.get("action").asText());

        // Check outcome (success)
        assertEquals("0", result.get("outcome").asText());

        // Check recorded timestamp
        assertTrue(result.get("recorded").asText().contains("2023"));

        // Check subtype
        JsonNode subtype = result.get("subtype").get(0);
        assertEquals("http://dicom.nema.org/resources/ontology/DCM", subtype.get("system").asText());
        assertEquals("110122", subtype.get("code").asText());
        assertEquals("Login", subtype.get("display").asText());

        // Check agent
        JsonNode agent = result.get("agent").get(0);
        assertTrue(agent.get("requestor").asBoolean());
        assertEquals("john.doe@example.com", agent.get("altId").asText());
        assertNotNull(agent.get("who").get("identifier").get("system"));
        assertEquals("192.168.1.100", agent.get("network").get("address").asText());
        assertEquals("2", agent.get("network").get("type").asText());

        // Check source
        JsonNode source = result.get("source");
        // Site should use real realm
        assertEquals("test-realm", source.get("site").asText());
        assertEquals("Keycloak", source.get("observer").get("display").asText());
        JsonNode observerIdentifier = source.get("observer").get("identifier");
        assertNotNull(observerIdentifier);
        assertEquals("https://keycloak.org/fhir/audit-event/realm", observerIdentifier.get("system").asText());
        // Observer value should use real realm
        assertEquals("test-realm", observerIdentifier.get("value").asText());
    }

    @Test
    void buildAuditEvent_LoginError_HasFailureOutcome() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("LOGIN_ERROR")
                .time(1700000000000L)
                .userId(null)
                .username("bad.user@example.com")
                .ipAddress("192.168.1.101")
                .realmId("test-realm")
                .clientId("my-app")
                .error("invalid_user_credentials")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        assertEquals("4", result.get("outcome").asText());
        assertEquals("invalid_user_credentials", result.get("outcomeDesc").asText());
    }

    @Test
    void buildAuditEvent_Logout_Success() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("LOGOUT")
                .time(1700000000000L)
                .userId("user-123")
                .username("john.doe@example.com")
                .ipAddress("192.168.1.100")
                .realmId("test-realm")
                .clientId("my-app")
                .sessionId("session-456")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);

        // Check subtype for logout
        JsonNode subtype = result.get("subtype").get(0);
        assertEquals("110123", subtype.get("code").asText());
        assertEquals("Logout", subtype.get("display").asText());
    }

    @Test
    void buildAuditEvent_DeleteAccount_DeleteAction() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("DELETE_ACCOUNT")
                .time(1700000000000L)
                .userId("user-789")
                .username("user@example.com")
                .ipAddress("192.168.1.102")
                .realmId("test-realm")
                .clientId("my-app")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        assertEquals("D", result.get("action").asText()); // Delete action
    }

    @Test
    void buildAuditEvent_AdminEvent_UsesDefaultMapping() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("ADMIN_CREATE")
                .time(1700000000000L)
                .userId("admin-user")
                .username("admin@example.com")
                .ipAddress("10.0.0.1")
                .realmId("test-realm")
                .clientId("admin-cli")
                .adminEvent(true)
                .resourceType("USER")
                .resourcePath("users/user-123")
                .operationType("CREATE")
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        // ADMIN_CREATE should use action "C" (Create) from YAML mapping
        assertEquals("C", result.get("action").asText());

        // Entity section should be present for admin events
        JsonNode entities = result.get("entity");
        assertNotNull(entities);
        assertTrue(entities.isArray());
        assertEquals(1, entities.size());
        
        // Verify entity structure
        JsonNode entity = entities.get(0);
        assertNotNull(entity.get("what"));
        assertNotNull(entity.get("type"));
        assertNotNull(entity.get("role"));
        assertEquals("users/user-123", entity.get("description").asText());
        assertNotNull(entity.get("query"));
    }

    @Test
    void buildAuditEvent_WithSessionAndClient_AddsEntities() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("LOGIN")
                .time(1700000000000L)
                .userId("user-123")
                .username("john.doe@example.com")
                .ipAddress("192.168.1.100")
                .realmId("test-realm")
                .clientId("my-app")
                .sessionId("session-456")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        // Entity section is removed to match auditbox expected format
        JsonNode entities = result.get("entity");
        assertNull(entities);
    }

    @Test
    void buildAuditEvent_NullEvent_ReturnsNull() {
        ObjectNode result = builder.buildAuditEvent(null);
        assertNull(result);
    }

    @Test
    void buildAuditEvent_UnknownEventType_UsesDefaults() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("UNKNOWN_TYPE")
                .time(1700000000000L)
                .userId("user-123")
                .username("john.doe@example.com")
                .ipAddress("192.168.1.100")
                .realmId("test-realm")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        // Should use default mapping
        JsonNode type = result.get("type");
        assertEquals("110100", type.get("code").asText());
    }

    @Test
    void buildAuditEvent_PasswordUpdate_UpdateAction() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("UPDATE_PASSWORD")
                .time(1700000000000L)
                .userId("user-123")
                .username("john.doe@example.com")
                .ipAddress("192.168.1.100")
                .realmId("test-realm")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        assertEquals("U", result.get("action").asText()); // Update action
    }

    @Test
    void buildAuditEvent_SendResetPassword_ExecuteAction() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("SEND_RESET_PASSWORD")
                .time(1700000000000L)
                .userId("user-123")
                .username("john.doe@example.com")
                .ipAddress("192.168.1.100")
                .realmId("test-realm")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        assertEquals("E", result.get("action").asText()); // Execute action
        assertEquals("0", result.get("outcome").asText()); // Success
    }

    @Test
    void buildAuditEvent_AllPasswordEvents_HaveCorrectMapping() {
        String[] passwordEvents = {
            "SEND_RESET_PASSWORD", "RESET_PASSWORD", "UPDATE_PASSWORD"
        };
        String[] expectedActions = {"E", "U", "U"};

        for (int i = 0; i < passwordEvents.length; i++) {
            NormalizedEvent event = NormalizedEvent.builder()
                    .type(passwordEvents[i])
                    .time(1700000000000L)
                    .userId("user-123")
                    .username("user@example.com")
                    .ipAddress("192.168.1.100")
                    .realmId("test-realm")
                    .adminEvent(false)
                    .build();

            ObjectNode result = builder.buildAuditEvent(event);
            assertNotNull(result, "Event type " + passwordEvents[i] + " should produce valid AuditEvent");
            assertEquals(expectedActions[i], result.get("action").asText(),
                    "Password event " + passwordEvents[i] + " should have action " + expectedActions[i]);
            assertEquals("0", result.get("outcome").asText(), "Password events should have success outcome");
        }
    }

    @Test
    void buildAuditEvent_AllErrorEvents_HaveFailureOutcome() {
        String[] errorEvents = {
            "LOGIN_ERROR", "CLIENT_LOGIN_ERROR",
            "SEND_RESET_PASSWORD_ERROR", "RESET_PASSWORD_ERROR",
            "UPDATE_PASSWORD_ERROR", "DELETE_ACCOUNT_ERROR"
        };

        for (String eventType : errorEvents) {
            NormalizedEvent event = NormalizedEvent.builder()
                    .type(eventType)
                    .time(1700000000000L)
                    .userId("user-123")
                    .username("user@example.com")
                    .ipAddress("192.168.1.100")
                    .realmId("test-realm")
                    .error("test_error")
                    .adminEvent(false)
                    .build();

            ObjectNode result = builder.buildAuditEvent(event);
            assertNotNull(result, "Error event type " + eventType + " should produce valid AuditEvent");
            assertEquals("4", result.get("outcome").asText(), "Error events should have failure outcome");
            assertEquals("test_error", result.get("outcomeDesc").asText(), "Error events should have outcomeDesc");
        }
    }

    @Test
    void buildAuditEvent_AllAdminEvents_HaveCorrectActions() {
        Map<String, String> expectedActions = Map.of(
                "ADMIN_CREATE", "C",
                "ADMIN_UPDATE", "U",
                "ADMIN_DELETE", "D",
                "ADMIN_ACTION", "E"
        );

        for (Map.Entry<String, String> entry : expectedActions.entrySet()) {
            String adminEventType = entry.getKey();
            String expectedAction = entry.getValue();

            NormalizedEvent event = NormalizedEvent.builder()
                    .type(adminEventType)
                    .time(1700000000000L)
                    .userId("admin-user")
                    .username("admin@example.com")
                    .ipAddress("10.0.0.1")
                    .realmId("test-realm")
                    .adminEvent(true)
                    .build();

            ObjectNode result = builder.buildAuditEvent(event);
            assertNotNull(result, "Admin event type " + adminEventType + " should produce valid AuditEvent");
            assertEquals(expectedAction, result.get("action").asText(),
                    "Admin event " + adminEventType + " should have action " + expectedAction);
            // Should use correct type code
            assertEquals("110100", result.get("type").get("code").asText());
        }
    }

    @Test
    void buildAuditEvent_MissingUsername_UsesUnknown() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("LOGIN")
                .time(1700000000000L)
                .userId("user-123")
                .username(null)
                .ipAddress("192.168.1.100")
                .realmId("test-realm")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        JsonNode agent = result.get("agent").get(0);
        assertEquals("unknown", agent.get("who").get("identifier").get("value").asText());
    }

    @Test
    void buildAuditEvent_MissingRealm_UsesUnknown() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("LOGIN")
                .time(1700000000000L)
                .userId("user-123")
                .username("user@example.com")
                .ipAddress("192.168.1.100")
                .realmId(null)
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        JsonNode source = result.get("source");
        assertEquals("unknown", source.get("site").asText());
        assertEquals("unknown", source.get("observer").get("identifier").get("value").asText());
    }

    @Test
    void buildAuditEvent_MissingIpAddress_NoNetworkField() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("LOGIN")
                .time(1700000000000L)
                .userId("user-123")
                .username("user@example.com")
                .ipAddress(null)
                .realmId("test-realm")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        JsonNode agent = result.get("agent").get(0);
        assertNull(agent.get("network"), "Network should be null when IP address is missing");
    }

    @Test
    void buildAuditEvent_UnknownIpAddress_NoNetworkField() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("LOGIN")
                .time(1700000000000L)
                .userId("user-123")
                .username("user@example.com")
                .ipAddress("unknown")
                .realmId("test-realm")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        JsonNode agent = result.get("agent").get(0);
        assertNull(agent.get("network"), "Network should be null when IP address is 'unknown'");
    }

    @Test
    void buildAuditEvent_AllRequiredFields_Present() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("LOGIN")
                .time(1700000000000L)
                .userId("user-123")
                .username("user@example.com")
                .ipAddress("192.168.1.100")
                .realmId("test-realm")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        // Required FHIR AuditEvent fields
        assertEquals("AuditEvent", result.get("resourceType").asText());
        assertNotNull(result.get("id"));
        assertNotNull(result.get("type"));
        assertNotNull(result.get("action"));
        assertNotNull(result.get("recorded"));
        assertNotNull(result.get("outcome"));
        assertNotNull(result.get("agent"));
        assertNotNull(result.get("source"));
    }

    @Test
    void buildAuditEvent_RecordedTimestamp_IsISOFormat() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("LOGIN")
                .time(1700000000000L) // 2023-11-14T22:13:20Z
                .userId("user-123")
                .username("user@example.com")
                .ipAddress("192.168.1.100")
                .realmId("test-realm")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        String recorded = result.get("recorded").asText();
        // Should be ISO 8601 format
        assertTrue(recorded.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z"),
                "Recorded timestamp should be in ISO 8601 format");
    }

    @Test
    void buildAuditEvent_AgentHasCorrectStructure() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("LOGIN")
                .time(1700000000000L)
                .userId("user-123")
                .username("user@example.com")
                .ipAddress("192.168.1.100")
                .realmId("test-realm")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        JsonNode agent = result.get("agent").get(0);
        assertNotNull(agent.get("type"));
        assertNotNull(agent.get("who"));
        assertNotNull(agent.get("who").get("identifier"));
        assertEquals("user@example.com", agent.get("altId").asText());
        assertTrue(agent.get("requestor").asBoolean());
        assertNotNull(agent.get("network"));
    }

    @Test
    void buildAuditEvent_SourceHasCorrectStructure() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("LOGIN")
                .time(1700000000000L)
                .userId("user-123")
                .username("user@example.com")
                .ipAddress("192.168.1.100")
                .realmId("test-realm")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        JsonNode source = result.get("source");
        assertNotNull(source.get("site"));
        assertNotNull(source.get("observer"));
        assertNotNull(source.get("observer").get("display"));
        assertNotNull(source.get("observer").get("identifier"));
        assertNotNull(source.get("type"));
        assertEquals("Keycloak", source.get("observer").get("display").asText());
    }

    @Test
    void buildAuditEvent_SubtypeForLoginEvents() {
        String[] loginEvents = {"LOGIN", "LOGIN_ERROR", "LOGOUT"};
        String[] expectedCodes = {"110122", "110122", "110123"};

        for (int i = 0; i < loginEvents.length; i++) {
            NormalizedEvent event = NormalizedEvent.builder()
                    .type(loginEvents[i])
                    .time(1700000000000L)
                    .userId("user-123")
                    .username("user@example.com")
                    .ipAddress("192.168.1.100")
                    .realmId("test-realm")
                    .adminEvent(false)
                    .build();

            ObjectNode result = builder.buildAuditEvent(event);
            assertNotNull(result);
            JsonNode subtype = result.get("subtype").get(0);
            assertEquals("http://dicom.nema.org/resources/ontology/DCM", subtype.get("system").asText());
            assertEquals(expectedCodes[i], subtype.get("code").asText());
        }
    }

    @Test
    void buildAuditEvent_UnknownEventType_UsesDefaultSubtype() {
        NormalizedEvent event = NormalizedEvent.builder()
                .type("UNKNOWN_EVENT_TYPE")
                .time(1700000000000L)
                .userId("user-123")
                .username("user@example.com")
                .ipAddress("192.168.1.100")
                .realmId("test-realm")
                .adminEvent(false)
                .build();

        ObjectNode result = builder.buildAuditEvent(event);

        assertNotNull(result);
        JsonNode subtype = result.get("subtype").get(0);
        // Should use Keycloak-specific system for unknown events
        assertTrue(subtype.get("system").asText().contains("keycloak.org"));
        assertEquals("UNKNOWN_EVENT_TYPE", subtype.get("code").asText());
    }
}

