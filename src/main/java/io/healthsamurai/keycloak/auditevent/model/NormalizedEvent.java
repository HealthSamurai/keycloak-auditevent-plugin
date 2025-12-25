package io.healthsamurai.keycloak.auditevent.model;

import java.util.Map;
import lombok.Builder;
import lombok.Getter;

/**
 * Normalized representation of a Keycloak event, ready for conversion to FHIR AuditEvent.
 */
@Getter
@Builder
public class NormalizedEvent {

    /** Event type (e.g., LOGIN, LOGOUT, LOGIN_ERROR) */
    private final String type;

    /** Event timestamp in milliseconds */
    private final long time;

    /** User ID from Keycloak */
    private final String userId;

    /** Username (email or login) */
    private final String username;

    /** Client IP address */
    private final String ipAddress;

    /** Keycloak realm ID */
    private final String realmId;

    /** Client ID (application) */
    private final String clientId;

    /** Session ID */
    private final String sessionId;

    /** Error message (for error events) */
    private final String error;

    /** Authentication method used */
    private final String authMethod;

    /** Whether this is an admin event */
    private final boolean adminEvent;

    /** Resource type (for admin events) */
    private final String resourceType;

    /** Resource path (for admin events) */
    private final String resourcePath;

    /** Operation type (for admin events) */
    private final String operationType;

    /** Resource representation JSON (for admin events with includeRepresentation=true) */
    private final String representation;

    /** Additional event details */
    private final Map<String, String> details;
}
