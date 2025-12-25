package io.healthsamurai.keycloak.auditevent.builder;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Tests for EventMappingLoader.
 */
class EventMappingLoaderTest {

    @Test
    void loadEventMappings_LoadsFromYaml() {
        Map<String, EventMappingLoader.EventTypeMapping> mappings = EventMappingLoader.loadEventMappings();

        assertNotNull(mappings);
        assertFalse(mappings.isEmpty(), "Event mappings should not be empty");

        // Check some known mappings
        EventMappingLoader.EventTypeMapping loginMapping = mappings.get("LOGIN");
        assertNotNull(loginMapping, "LOGIN mapping should exist");
        assertEquals("110114", loginMapping.code());
        assertEquals("User Authentication", loginMapping.display());
        assertEquals("E", loginMapping.action());
        assertEquals("0", loginMapping.outcome());
        assertNotNull(loginMapping.subtype(), "LOGIN subtype should exist");
        assertEquals("http://dicom.nema.org/resources/ontology/DCM", loginMapping.subtype().system());
        assertEquals("110122", loginMapping.subtype().code());
        assertEquals("Login", loginMapping.subtype().display());

        EventMappingLoader.EventTypeMapping updatePasswordMapping = mappings.get("UPDATE_PASSWORD");
        assertNotNull(updatePasswordMapping, "UPDATE_PASSWORD mapping should exist");
        assertEquals("110100", updatePasswordMapping.code());
        assertEquals("Application Activity", updatePasswordMapping.display());
        assertEquals("U", updatePasswordMapping.action());
    }

    @Test
    void loadDefaultMapping_LoadsFromYaml() {
        EventMappingLoader.EventTypeMapping defaultMapping = EventMappingLoader.loadDefaultMapping();

        assertNotNull(defaultMapping);
        assertEquals("110100", defaultMapping.code());
        assertEquals("Application Activity", defaultMapping.display());
        assertEquals("E", defaultMapping.action());
        assertEquals("0", defaultMapping.outcome());
    }

    @Test
    void loadEventMappings_ContainsAllExpectedEvents() {
        Map<String, EventMappingLoader.EventTypeMapping> mappings = EventMappingLoader.loadEventMappings();

        String[] expectedEvents = {
            "LOGIN", "LOGIN_ERROR", "LOGOUT",
            "CLIENT_LOGIN", "CLIENT_LOGIN_ERROR",
            "SEND_RESET_PASSWORD", "SEND_RESET_PASSWORD_ERROR",
            "RESET_PASSWORD", "RESET_PASSWORD_ERROR",
            "UPDATE_PASSWORD", "UPDATE_PASSWORD_ERROR",
            "DELETE_ACCOUNT", "DELETE_ACCOUNT_ERROR"
        };

        for (String eventType : expectedEvents) {
            assertTrue(mappings.containsKey(eventType),
                    "Event mapping for " + eventType + " should exist");
        }
    }

    @Test
    void eventMappingsContainSubtypesWhereProvided() {
        Map<String, EventMappingLoader.EventTypeMapping> mappings = EventMappingLoader.loadEventMappings();

        EventMappingLoader.EventTypeMapping login = mappings.get("LOGIN");
        assertNotNull(login.subtype(), "LOGIN should have subtype");

        EventMappingLoader.EventTypeMapping logout = mappings.get("LOGOUT");
        assertNotNull(logout.subtype(), "LOGOUT should have subtype");

        EventMappingLoader.EventTypeMapping clientLogin = mappings.get("CLIENT_LOGIN");
        assertNull(clientLogin.subtype(), "CLIENT_LOGIN should not have subtype unless configured");
    }

    @Test
    void loadEventMappings_VariablesAreReplaced() {
        Map<String, EventMappingLoader.EventTypeMapping> mappings = EventMappingLoader.loadEventMappings();

        // Check that LOGIN event has DICOM system replaced from $dicom variable
        EventMappingLoader.EventTypeMapping loginMapping = mappings.get("LOGIN");
        assertNotNull(loginMapping, "LOGIN mapping should exist");
        assertNotNull(loginMapping.subtype(), "LOGIN should have subtype");
        assertEquals("http://dicom.nema.org/resources/ontology/DCM", loginMapping.subtype().system(),
                "DICOM system should be replaced from $dicom variable");

        // Check UPDATE_PASSWORD also uses the variable
        EventMappingLoader.EventTypeMapping updatePasswordMapping = mappings.get("UPDATE_PASSWORD");
        assertNotNull(updatePasswordMapping, "UPDATE_PASSWORD mapping should exist");
        assertNotNull(updatePasswordMapping.subtype(), "UPDATE_PASSWORD should have subtype");
        assertEquals("http://dicom.nema.org/resources/ontology/DCM", updatePasswordMapping.subtype().system(),
                "DICOM system should be replaced from $dicom variable");
    }
}

