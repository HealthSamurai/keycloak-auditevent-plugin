package io.healthsamurai.keycloak.auditevent;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.healthsamurai.keycloak.auditevent.builder.AuditEventBuilder;
import io.healthsamurai.keycloak.auditevent.client.FhirClient;
import io.healthsamurai.keycloak.auditevent.config.PluginConfig;
import io.healthsamurai.keycloak.auditevent.extractor.EventExtractor;
import io.healthsamurai.keycloak.auditevent.model.NormalizedEvent;
import io.healthsamurai.keycloak.auditevent.util.JsonUtil;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Keycloak Event Listener Provider that converts events to FHIR R4 AuditEvents
 * and sends them to a configured FHIR server.
 *
 * <p>This provider intercepts Keycloak authentication events (LOGIN, LOGOUT, etc.)
 * and admin events, converts them to FHIR R4 AuditEvent resources, and forwards
 * them to a FHIR server endpoint via HTTP POST.
 */
public class FhirAuditEventProvider implements EventListenerProvider {

    private static final Logger log = LoggerFactory.getLogger(FhirAuditEventProvider.class);

    private final KeycloakSession session;
    private final EventExtractor eventExtractor;
    private final AuditEventBuilder auditEventBuilder;
    private final FhirClient fhirClient;
    private final boolean adminEventsEnabled;
    private final boolean debugEnabled;

    /**
     * Creates a new provider instance.
     *
     * @param session The Keycloak session
     * @param fhirClient The FHIR client for sending events
     */
    public FhirAuditEventProvider(KeycloakSession session, FhirClient fhirClient) {
        this.session = session;
        this.fhirClient = fhirClient;
        this.eventExtractor = new EventExtractor();
        this.auditEventBuilder = new AuditEventBuilder();
        this.adminEventsEnabled = PluginConfig.isAdminEventsEnabled();
        this.debugEnabled = PluginConfig.isDebugEnabled();

        log.debug("FhirAuditEventProvider created for session, admin events: {}, debug: {}",
                adminEventsEnabled, debugEnabled);
    }

    /**
     * Handles user events from Keycloak.
     *
     * @param event The Keycloak user event
     */
    @Override
    public void onEvent(Event event) {
        if (event == null) {
            log.warn("Received null event");
            return;
        }

        try {
            log.debug("Processing user event: {} for user: {} in realm: {}",
                    event.getType(), event.getUserId(), event.getRealmId());

            // Debug: log original Keycloak event
            if (debugEnabled) {
                logOriginalKeycloakEvent(event);
            }

            // Extract normalized event data (with session for user lookup by ID)
            NormalizedEvent normalizedEvent = eventExtractor.extractUserEvent(event, session);

            if (normalizedEvent == null) {
                log.debug("Event type {} not supported for AuditEvent conversion", event.getType());
                return;
            }

            // Build FHIR AuditEvent
            ObjectNode auditEvent = auditEventBuilder.buildAuditEvent(normalizedEvent);

            if (auditEvent == null) {
                log.warn("Failed to build AuditEvent for event type: {}", event.getType());
                return;
            }

            // Debug: log generated AuditEvent
            if (debugEnabled) {
                logAuditEvent(auditEvent);
            }

            // Send to FHIR server
            fhirClient.sendAuditEvent(auditEvent);

            log.info("Processed {} event for user {} in realm {}",
                    event.getType(), event.getUserId(), event.getRealmId());

        } catch (Exception e) {
            log.error("Error processing user event {}: {} - {}",
                    event.getType(), e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Full error:", e);
            }
        }
    }

    /**
     * Handles admin events from Keycloak.
     *
     * @param adminEvent The Keycloak admin event
     * @param includeRepresentation Whether to include the resource representation
     */
    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        if (adminEvent == null) {
            log.warn("Received null admin event");
            return;
        }

        if (!adminEventsEnabled) {
            log.debug("Admin events disabled, skipping: {}", adminEvent.getOperationType());
            return;
        }

        try {
            log.debug("Processing admin event: {} on resource: {} in realm: {} (includeRepresentation: {})",
                    adminEvent.getOperationType(),
                    adminEvent.getResourcePath(),
                    adminEvent.getRealmId(),
                    includeRepresentation);

            // Debug: log original Keycloak admin event
            if (debugEnabled) {
                logOriginalKeycloakAdminEvent(adminEvent, includeRepresentation);
            }

            // Extract normalized event data (with session for admin username lookup)
            // Note: representation will be available via adminEvent.getRepresentation() 
            // if includeRepresentation=true in Keycloak settings
            NormalizedEvent normalizedEvent = eventExtractor.extractAdminEvent(adminEvent, session);

            if (normalizedEvent == null) {
                log.warn("Failed to extract admin event data");
                return;
            }


            // Build FHIR AuditEvent
            ObjectNode auditEvent = auditEventBuilder.buildAuditEvent(normalizedEvent);

            if (auditEvent == null) {
                log.warn("Failed to build AuditEvent for admin event: {}",
                        adminEvent.getOperationType());
                return;
            }

            // Debug: log generated AuditEvent
            if (debugEnabled) {
                logAuditEvent(auditEvent);
            }

            // Send to FHIR server
            fhirClient.sendAuditEvent(auditEvent);

            log.info("Processed admin {} event on {} in realm {}",
                    adminEvent.getOperationType(),
                    adminEvent.getResourcePath(),
                    adminEvent.getRealmId());

        } catch (Exception e) {
            log.error("Error processing admin event {}: {} - {}",
                    adminEvent.getOperationType(),
                    e.getClass().getSimpleName(),
                    e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Full error:", e);
            }
        }
    }

    /**
     * Closes this provider and releases resources.
     */
    @Override
    public void close() {
        log.debug("Closing FhirAuditEventProvider");
        // FhirClient is shared, don't close it here
    }

    /**
     * Logs the original Keycloak user event in debug mode.
     */
    private void logOriginalKeycloakEvent(Event event) {
        try {
            ObjectNode eventJson = JsonUtil.createObjectNode();
            eventJson.put("type", event.getType() != null ? event.getType().toString() : "null");
            eventJson.put("time", event.getTime());
            eventJson.put("userId", event.getUserId());
            eventJson.put("ipAddress", event.getIpAddress());
            eventJson.put("realmId", event.getRealmId());
            eventJson.put("clientId", event.getClientId());
            eventJson.put("sessionId", event.getSessionId());
            eventJson.put("error", event.getError());
            if (event.getDetails() != null) {
                ObjectNode details = JsonUtil.createObjectNode();
                event.getDetails().forEach(details::put);
                eventJson.set("details", details);
            }

            log.info("[DEBUG] Original Keycloak Event:\n{}", JsonUtil.toPrettyJson(eventJson));
        } catch (Exception e) {
            log.warn("Failed to serialize original Keycloak event for debug logging: {}", e.getMessage());
        }
    }

    /**
     * Logs the original Keycloak admin event in debug mode.
     *
     * @param adminEvent The admin event
     * @param includeRepresentation Whether representation is included (from Keycloak settings)
     */
    private void logOriginalKeycloakAdminEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        try {
            ObjectNode eventJson = JsonUtil.createObjectNode();
            eventJson.put("operationType", adminEvent.getOperationType() != null
                    ? adminEvent.getOperationType().toString() : "null");
            eventJson.put("resourceType", adminEvent.getResourceType() != null
                    ? adminEvent.getResourceType().toString() : "null");
            eventJson.put("time", adminEvent.getTime());
            eventJson.put("realmId", adminEvent.getRealmId());
            eventJson.put("resourcePath", adminEvent.getResourcePath());
            eventJson.put("error", adminEvent.getError());
            eventJson.put("includeRepresentation", includeRepresentation);

            if (adminEvent.getAuthDetails() != null) {
                ObjectNode authDetails = JsonUtil.createObjectNode();
                authDetails.put("userId", adminEvent.getAuthDetails().getUserId());
                authDetails.put("ipAddress", adminEvent.getAuthDetails().getIpAddress());
                authDetails.put("clientId", adminEvent.getAuthDetails().getClientId());
                eventJson.set("authDetails", authDetails);
            }

            // Include representation if available
            String representation = adminEvent.getRepresentation();
            if (representation != null && !representation.trim().isEmpty()) {
                try {
                    com.fasterxml.jackson.databind.JsonNode repNode = JsonUtil.parseJson(representation);
                    if (repNode != null) {
                        eventJson.set("representation", repNode);
                    } else {
                        eventJson.put("representation", representation);
                    }
                } catch (Exception e) {
                    eventJson.put("representation", representation);
                }
            }

            String prettyJson = JsonUtil.toPrettyJson(eventJson);
            log.info("[DEBUG] Original Keycloak Admin Event:\n{}", prettyJson);
        } catch (Exception e) {
            log.warn("Failed to serialize original Keycloak admin event for debug logging: {}", e.getMessage());
        }
    }

    /**
     * Logs the generated FHIR AuditEvent in debug mode.
     */
    private void logAuditEvent(ObjectNode auditEvent) {
        try {
            log.info("[DEBUG] Generated FHIR AuditEvent:\n{}", JsonUtil.toPrettyJson(auditEvent));
        } catch (Exception e) {
            log.warn("Failed to serialize AuditEvent for debug logging: {}", e.getMessage());
        }
    }
}

