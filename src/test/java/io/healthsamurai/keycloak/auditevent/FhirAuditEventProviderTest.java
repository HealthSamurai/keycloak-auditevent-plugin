package io.healthsamurai.keycloak.auditevent;

import static org.junit.jupiter.api.Assertions.*;

import io.healthsamurai.keycloak.auditevent.client.FhirClient;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.admin.AdminEvent;

/**
 * Tests for FhirAuditEventProvider.
 * Tests null handling without mocking.
 */
class FhirAuditEventProviderTest {

    @Test
    void onEvent_NullUserEvent_DoesNotThrow() {
        FhirClient client = new FhirClient();
        FhirAuditEventProvider provider = new FhirAuditEventProvider(null, client);

        assertDoesNotThrow(() -> provider.onEvent((Event) null));

        provider.close();
        client.close();
    }

    @Test
    void onEvent_NullAdminEvent_DoesNotThrow() {
        FhirClient client = new FhirClient();
        FhirAuditEventProvider provider = new FhirAuditEventProvider(null, client);

        assertDoesNotThrow(() -> provider.onEvent((AdminEvent) null, false));

        provider.close();
        client.close();
    }

    @Test
    void close_DoesNotThrow() {
        FhirClient client = new FhirClient();
        FhirAuditEventProvider provider = new FhirAuditEventProvider(null, client);

        assertDoesNotThrow(provider::close);

        client.close();
    }
}
