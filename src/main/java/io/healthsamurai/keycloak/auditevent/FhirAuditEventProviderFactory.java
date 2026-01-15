package io.healthsamurai.keycloak.auditevent;

import io.healthsamurai.keycloak.auditevent.client.FhirClient;
import io.healthsamurai.keycloak.auditevent.config.PluginConfig;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.Properties;

/**
 * Factory for creating FhirAuditEventProvider instances.
 *
 * <p>This factory is registered with Keycloak through the SPI mechanism and is responsible
 * for creating event listener providers that convert Keycloak events to FHIR AuditEvents.
 */
public class FhirAuditEventProviderFactory implements EventListenerProviderFactory {

    private static final Logger log = LoggerFactory.getLogger(FhirAuditEventProviderFactory.class);

    /** Provider ID used in Keycloak configuration */
    public static final String PROVIDER_ID = "fhir-auditevent";

    private FhirClient fhirClient;

    /**
     * Creates a new event listener provider for the given session.
     *
     * @param session The Keycloak session
     * @return A new FhirAuditEventProvider instance
     */
    @Override
    public EventListenerProvider create(KeycloakSession session) {
        log.debug("Creating FhirAuditEventProvider for session");
        // Create FhirClient with session for internal token provider support
        FhirClient clientWithSession = new FhirClient(session);
        return new FhirAuditEventProvider(session, clientWithSession);
    }

    /**
     * Initializes the factory with configuration from Keycloak.
     *
     * @param config The Keycloak configuration scope
     */
    @Override
    public void init(Config.Scope config) {
        log.info("Initializing FhirAuditEventProviderFactory");

        // Log git commit info
        logGitInfo();

        log.info("FHIR Server URL: {}", PluginConfig.getFhirServerUrl());
        log.info("Auth Type: {}", PluginConfig.getAuthType());
        log.info("Admin Events Enabled: {}", PluginConfig.isAdminEventsEnabled());
        log.info("Async Enabled: {}", PluginConfig.isAsyncEnabled());

        // Create shared FhirClient instance
        this.fhirClient = new FhirClient();
    }

    /**
     * Logs git commit information from git.properties file.
     */
    private void logGitInfo() {
        // Try multiple ways to load git.properties
        InputStream input = FhirAuditEventProviderFactory.class.getResourceAsStream("/git.properties");
        if (input == null) {
            input = Thread.currentThread().getContextClassLoader().getResourceAsStream("git.properties");
        }
        if (input == null) {
            input = getClass().getClassLoader().getResourceAsStream("git.properties");
        }

        if (input != null) {
            try {
                Properties props = new Properties();
                props.load(input);

                String commitId = props.getProperty("git.commit.id.abbrev", "unknown");
                String branch = props.getProperty("git.branch", "unknown");
                String buildTime = props.getProperty("git.build.time", "unknown");
                String dirty = props.getProperty("git.dirty", "false");

                String dirtyMarker = "true".equals(dirty) ? " (dirty)" : "";
                log.info("Git: commit={}{}, branch={}, build={}", commitId, dirtyMarker, branch, buildTime);
            } catch (Exception e) {
                log.warn("Could not load git.properties: {}", e.getMessage());
            } finally {
                try {
                    input.close();
                } catch (Exception ignored) {}
            }
        } else {
            log.info("Git: commit=unknown (git.properties not found)");
        }
    }

    /**
     * Called after all provider factories have been initialized.
     *
     * @param factory The Keycloak session factory
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        log.info("FhirAuditEventProviderFactory post-initialization complete");
    }

    /**
     * Closes the factory and releases resources.
     */
    @Override
    public void close() {
        log.info("Closing FhirAuditEventProviderFactory");
        if (fhirClient != null) {
            fhirClient.close();
        }
    }

    /**
     * Returns the unique ID for this provider factory.
     *
     * @return The provider ID "fhir-auditevent"
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}

