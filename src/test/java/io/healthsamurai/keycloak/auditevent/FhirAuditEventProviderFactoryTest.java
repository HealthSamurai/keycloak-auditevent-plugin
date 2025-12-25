package io.healthsamurai.keycloak.auditevent;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/**
 * Tests for FhirAuditEventProviderFactory.
 */
class FhirAuditEventProviderFactoryTest {

    @Test
    void getId_ReturnsFhirAuditevent() {
        FhirAuditEventProviderFactory factory = new FhirAuditEventProviderFactory();
        assertEquals("fhir-auditevent", factory.getId());
    }

    @Test
    void init_DoesNotThrow() {
        FhirAuditEventProviderFactory factory = new FhirAuditEventProviderFactory();
        assertDoesNotThrow(() -> factory.init(null));
    }

    @Test
    void postInit_DoesNotThrow() {
        FhirAuditEventProviderFactory factory = new FhirAuditEventProviderFactory();
        factory.init(null);
        assertDoesNotThrow(() -> factory.postInit(null));
    }

    @Test
    void close_DoesNotThrow() {
        FhirAuditEventProviderFactory factory = new FhirAuditEventProviderFactory();
        factory.init(null);
        assertDoesNotThrow(factory::close);
    }

    @Test
    void create_ReturnsProvider() {
        FhirAuditEventProviderFactory factory = new FhirAuditEventProviderFactory();
        factory.init(null);

        var provider = factory.create(null);
        assertNotNull(provider);

        provider.close();
        factory.close();
    }
}

