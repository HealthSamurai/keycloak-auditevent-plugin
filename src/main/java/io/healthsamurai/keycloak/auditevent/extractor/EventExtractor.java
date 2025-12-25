package io.healthsamurai.keycloak.auditevent.extractor;

import io.healthsamurai.keycloak.auditevent.builder.EventMappingLoader;
import io.healthsamurai.keycloak.auditevent.model.NormalizedEvent;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.keycloak.events.Event;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extracts and normalizes data from Keycloak events for conversion to FHIR AuditEvent.
 */
public class EventExtractor {

    private static final Logger log = LoggerFactory.getLogger(EventExtractor.class);

    /** Supported user event types for AuditEvent conversion (YAML-driven) */
    private static final Set<String> SUPPORTED_USER_EVENTS = EventMappingLoader.loadSupportedEventTypes();

    /**
     * Extracts normalized data from a Keycloak user event.
     *
     * @param event The Keycloak user event
     * @return NormalizedEvent or null if event type is not supported
     */
    public NormalizedEvent extractUserEvent(Event event) {
        return extractUserEvent(event, null);
    }

    /**
     * Extracts normalized data from a Keycloak user event with optional session for user lookup.
     *
     * @param event The Keycloak user event
     * @param session Optional Keycloak session for user lookup by ID
     * @return NormalizedEvent or null if event type is not supported
     */
    public NormalizedEvent extractUserEvent(Event event, KeycloakSession session) {
        if (event == null) {
            log.warn("Received null user event");
            return null;
        }

        String eventType = event.getType() != null ? event.getType().toString() : "UNKNOWN";

        if (!SUPPORTED_USER_EVENTS.contains(eventType)) {
            log.debug("Unsupported user event type: {}", eventType);
            return null;
        }

        Map<String, String> details = event.getDetails() != null
                ? new HashMap<>(event.getDetails())
                : new HashMap<>();

        String username = extractUsername(details, event.getUserId(), event.getRealmId(), session);

        return NormalizedEvent.builder()
                .type(eventType)
                .time(event.getTime())
                .userId(event.getUserId())
                .username(username)
                .ipAddress(event.getIpAddress() != null ? event.getIpAddress() : "unknown")
                .realmId(event.getRealmId() != null ? event.getRealmId() : "unknown")
                .clientId(event.getClientId())
                .sessionId(event.getSessionId())
                .error(event.getError())
                .authMethod(details.getOrDefault("auth_method",
                        details.getOrDefault("auth_type", "unknown")))
                .adminEvent(false)
                .details(details)
                .build();
    }

    /**
     * Extracts normalized data from a Keycloak admin event.
     *
     * @param adminEvent The Keycloak admin event
     * @return NormalizedEvent
     */
    public NormalizedEvent extractAdminEvent(AdminEvent adminEvent) {
        return extractAdminEvent(adminEvent, null);
    }

    /**
     * Extracts normalized data from a Keycloak admin event with optional session for admin user lookup.
     *
     * @param adminEvent The Keycloak admin event
     * @param session Optional Keycloak session for admin user lookup by ID
     * @return NormalizedEvent
     */
    public NormalizedEvent extractAdminEvent(AdminEvent adminEvent, KeycloakSession session) {
        if (adminEvent == null) {
            log.warn("Received null admin event");
            return null;
        }

        String operationType = adminEvent.getOperationType() != null
                ? adminEvent.getOperationType().toString()
                : "UNKNOWN";

        String resourceType = adminEvent.getResourceType() != null
                ? adminEvent.getResourceType().toString()
                : "UNKNOWN";

        String adminUserId = adminEvent.getAuthDetails() != null
                ? adminEvent.getAuthDetails().getUserId()
                : null;

        // Extract admin username - try to lookup by ID if session is available
        String adminUsername = "admin"; // default fallback
        if (adminUserId != null) {
            if (session != null && adminEvent.getRealmId() != null) {
                // Try to lookup admin username by ID
                adminUsername = extractUsername(new HashMap<>(), adminUserId, adminEvent.getRealmId(), session);
            } else {
                // Fallback to userId if session not available
                adminUsername = adminUserId;
            }
        }

        // Extract representation if available
        String representation = null;
        
        String representationJson = adminEvent.getRepresentation();
        if (representationJson != null && !representationJson.trim().isEmpty()) {
            representation = representationJson;
            log.debug("Representation received for {} operation on {}: {} bytes", 
                    operationType, resourceType, representationJson.length());
        } else {
            log.debug("No representation available for {} operation on {}", operationType, resourceType);
        }

        return NormalizedEvent.builder()
                .type("ADMIN_" + operationType)
                .time(adminEvent.getTime())
                .userId(adminUserId)
                .username(adminUsername)
                .ipAddress(adminEvent.getAuthDetails() != null
                        ? adminEvent.getAuthDetails().getIpAddress()
                        : "unknown")
                .realmId(adminEvent.getRealmId() != null ? adminEvent.getRealmId() : "unknown")
                .clientId(adminEvent.getAuthDetails() != null
                        ? adminEvent.getAuthDetails().getClientId()
                        : null)
                .error(adminEvent.getError())
                .adminEvent(true)
                .resourceType(resourceType)
                .resourcePath(adminEvent.getResourcePath())
                .operationType(operationType)
                .representation(representation)
                .build();
    }

    /**
     * Extracts username from event details, or looks up user by ID if session is available.
     */
    private String extractUsername(Map<String, String> details, String userId, String realmId, KeycloakSession session) {
        // First priority: username from event details
        String username = details.get("username");
        if (username != null && !username.isEmpty()) {
            return username;
        }

        // Second priority: lookup username through session if available
        if (userId != null && session != null && realmId != null) {
            try {
                RealmModel realm = session.realms().getRealm(realmId);
                if (realm != null) {
                    UserModel user = session.users().getUserById(realm, userId);
                    if (user != null) {
                        username = user.getUsername();
                        if (username != null && !username.isEmpty()) {
                            log.debug("Retrieved username from Keycloak user lookup: {}", username);
                            return username;
                        }
                    }
                }
            } catch (Exception e) {
                log.debug("Failed to lookup user by ID {} in realm {}: {}", userId, realmId, e.getMessage());
            }
        }

        // Third priority: fallback to userId or email
        if (userId != null) {
            return userId;
        }
        
        // Last resort: try email from details
        String email = details.get("email");
        if (email != null && !email.isEmpty()) {
            return email;
        }
        
        return "unknown";
    }

    /**
     * Checks if the given event type is supported.
     *
     * @param eventType The event type to check
     * @return true if supported
     */
    public boolean isSupported(String eventType) {
        return eventType != null && SUPPORTED_USER_EVENTS.contains(eventType);
    }
}

