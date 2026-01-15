package io.healthsamurai.keycloak.auditevent.builder;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.healthsamurai.keycloak.auditevent.model.NormalizedEvent;
import io.healthsamurai.keycloak.auditevent.util.JsonUtil;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds FHIR R4 AuditEvent resources from normalized Keycloak events.
 * Creates standards-compliant FHIR AuditEvent JSON that can be sent to any FHIR R4 server.
 */
public class AuditEventBuilder {

    private static final Logger log = LoggerFactory.getLogger(AuditEventBuilder.class);

    // FHIR Code Systems
    private static final String AUDIT_EVENT_TYPE_SYSTEM =
            "http://terminology.hl7.org/CodeSystem/audit-event-type";
    private static final String DICOM_SYSTEM =
            "http://dicom.nema.org/resources/ontology/DCM";
    private static final String SECURITY_ROLE_SYSTEM =
            "http://terminology.hl7.org/CodeSystem/extra-security-role-type";
    private static final String SECURITY_SOURCE_SYSTEM =
            "http://terminology.hl7.org/CodeSystem/security-source-type";
    private static final String KEYCLOAK_SYSTEM =
            "https://keycloak.org/fhir/audit-event";

    // Event type mappings loaded from YAML configuration
    private static final Map<String, EventMappingLoader.EventTypeMapping> EVENT_MAPPINGS =
            EventMappingLoader.loadEventMappings();

    // Default mapping loaded from YAML configuration
    private static final EventMappingLoader.EventTypeMapping DEFAULT_MAPPING =
            EventMappingLoader.loadDefaultMapping();

    /**
     * Builds a FHIR R4 AuditEvent from a normalized Keycloak event.
     *
     * @param event The normalized event
     * @return ObjectNode representing the FHIR AuditEvent, or null if event is null
     */
    public ObjectNode buildAuditEvent(NormalizedEvent event) {
        if (event == null) {
            log.warn("Cannot build AuditEvent from null event");
            return null;
        }

        ObjectNode auditEvent = JsonUtil.createObjectNode();

        // Resource metadata
        auditEvent.put("resourceType", "AuditEvent");
        auditEvent.put("id", UUID.randomUUID().toString());

        // Get event type mapping from YAML configuration
        EventMappingLoader.EventTypeMapping mapping = EVENT_MAPPINGS.getOrDefault(
                event.getType(),
                DEFAULT_MAPPING
        );

        // Type (required)
        addType(auditEvent, mapping);

        // Subtype
        addSubtype(auditEvent, event, mapping);

        // Action (required)
        auditEvent.put("action", mapping.action());

        // Recorded timestamp (required)
        String recorded = Instant.ofEpochMilli(event.getTime())
                .atOffset(java.time.ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_INSTANT);
        auditEvent.put("recorded", recorded);

        // Outcome from mapping (YAML-driven)
        String outcome = mapping.outcome() != null ? mapping.outcome() : "0";
        auditEvent.put("outcome", outcome);

        // Outcome description (for errors)
        if (event.getError() != null) {
            auditEvent.put("outcomeDesc", event.getError());
        }

        // Agent (required) - the user/client performing the action
        addAgent(auditEvent, event);

        // Source (required) - Keycloak server info
        addSource(auditEvent, event);

        // Entity - for admin events, add the resource that was modified
        if (event.isAdminEvent()) {
            addEntity(auditEvent, event);
        }

        return auditEvent;
    }

    private void addType(ObjectNode auditEvent, EventMappingLoader.EventTypeMapping mapping) {
        ObjectNode type = auditEvent.putObject("type");
        // Use DICOM system for authentication events to match canonical format
        type.put("system", DICOM_SYSTEM);
        type.put("code", mapping.code());
        type.put("display", mapping.display());
    }

    private void addSubtype(ObjectNode auditEvent, NormalizedEvent event, EventMappingLoader.EventTypeMapping mapping) {
        // Skip subtype for admin events
        if (event.isAdminEvent()) {
            return;
        }

        ArrayNode subtypeArray = auditEvent.putArray("subtype");
        ObjectNode subtype = subtypeArray.addObject();

        EventMappingLoader.SubtypeMapping subtypeMapping = mapping.subtype();
        if (subtypeMapping != null) {
            subtype.put("system", subtypeMapping.system());
            subtype.put("code", subtypeMapping.code());
            subtype.put("display", subtypeMapping.display());
        } else {
            // Use Keycloak-specific subtype for non-admin events
            subtype.put("system", KEYCLOAK_SYSTEM);
            subtype.put("code", event.getType());
            subtype.put("display", formatEventType(event.getType()));
        }
    }

    private void addAgent(ObjectNode auditEvent, NormalizedEvent event) {
        ArrayNode agentArray = auditEvent.putArray("agent");
        ObjectNode agent = agentArray.addObject();

        // Agent type
        ObjectNode agentType = agent.putObject("type");
        ArrayNode typeCoding = agentType.putArray("coding");
        ObjectNode coding = typeCoding.addObject();
        coding.put("system", SECURITY_ROLE_SYSTEM);
        coding.put("code", "humanuser");
        coding.put("display", "human user");

        // Who (identifier) - matches canonical format with system
        ObjectNode whoNode = agent.putObject("who");
        ObjectNode whoIdNode = whoNode.putObject("identifier");
        whoIdNode.put("system", KEYCLOAK_SYSTEM + "/users");
        
        // For admin events, use userId (from authDetails.userId) instead of username
        String whoValue;
        if (event.isAdminEvent()) {
            whoValue = event.getUserId() != null ? event.getUserId() : "unknown";
        } else {
            whoValue = event.getUsername() != null ? event.getUsername() : "unknown";
        }
        whoIdNode.put("value", whoValue);

        // Alt ID - username (if available)
        if (event.getUsername() != null) {
            agent.put("altId", event.getUsername());
        }

        // Requestor
        agent.put("requestor", true);

        // Network (with type - matches canonical format)
        if (event.getIpAddress() != null && !event.getIpAddress().equals("unknown")) {
            ObjectNode network = agent.putObject("network");
            network.put("address", event.getIpAddress());
            network.put("type", "2");
        }
    }

    private void addSource(ObjectNode auditEvent, NormalizedEvent event) {
        ObjectNode source = auditEvent.putObject("source");

        // Site - use realm as identifier of the source system
        String site = event.getRealmId() != null && !event.getRealmId().equals("unknown")
                ? event.getRealmId()
                : "unknown";
        source.put("site", site);

        // Source observer - the system/device generating the event
        ObjectNode observerNode = source.putObject("observer");
        observerNode.put("display", "Keycloak");
        ObjectNode realmIdNode = observerNode.putObject("identifier");
        realmIdNode.put("system", "https://keycloak.org/fhir/audit-event/realm");
        // Use real realm from event
        String observerValue = event.getRealmId() != null && !event.getRealmId().equals("unknown")
                ? event.getRealmId()
                : "unknown";
        realmIdNode.put("value", observerValue);

        // Source type - code "6" (Security Server) for authentication/authorization server
        ArrayNode sourceTypeArray = source.putArray("type");
        ObjectNode sourceTypeCoding = sourceTypeArray.addObject();
        sourceTypeCoding.put("system", SECURITY_SOURCE_SYSTEM);
        sourceTypeCoding.put("code", "6");
        sourceTypeCoding.put("display", "Security Server");
    }

    private void addEntity(ObjectNode auditEvent, NormalizedEvent event) {
        ArrayNode entityArray = auditEvent.putArray("entity");

        // Add resource entity for admin events
        if (event.isAdminEvent() && event.getResourcePath() != null) {
            ObjectNode resourceEntity = entityArray.addObject();
            
            // What - identifier for the resource
            ObjectNode what = resourceEntity.putObject("what");
            ObjectNode identifier = what.putObject("identifier");
            identifier.put("system", KEYCLOAK_SYSTEM + "/" + event.getResourceType().toLowerCase());
            
            // Extract resource ID from resourcePath (format: "users/{userId}" or "clients/{clientId}")
            String resourceId = extractResourceId(event.getResourcePath());
            if (resourceId != null) {
                identifier.put("value", resourceId);
            } else {
                identifier.put("value", event.getResourcePath());
            }
            
            // Display name from representation if available
            String displayName = extractDisplayName(event);
            if (displayName != null) {
                what.put("display", displayName);
            }
            
            // Type - resource type (USER, CLIENT, etc.)
            ObjectNode type = resourceEntity.putObject("type");
            type.put("system", "http://hl7.org/fhir/resource-types");
            String resourceTypeCode = mapKeycloakResourceTypeToFhir(event.getResourceType());
            type.put("code", resourceTypeCode);
            type.put("display", event.getResourceType());

            // Description - resource path (without base64 encoding)
            resourceEntity.put("description", event.getResourcePath());
            
            // Query - base64-encoded resource path
            // Note: FHIR R4 constraint: either name OR query must be empty (not both)
            // We use query instead of name to comply with the constraint
            if (event.getResourcePath() != null) {
                String encodedPath = Base64.getEncoder().encodeToString(
                        event.getResourcePath().getBytes(StandardCharsets.UTF_8));
                resourceEntity.put("query", encodedPath);
            }
        }
    }
    
    /**
     * Extracts resource ID from resource path (e.g., "users/{userId}" -> userId).
     */
    private String extractResourceId(String resourcePath) {
        if (resourcePath == null) {
            return null;
        }
        int lastSlash = resourcePath.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < resourcePath.length() - 1) {
            return resourcePath.substring(lastSlash + 1);
        }
        return resourcePath;
    }
    
    /**
     * Extracts display name from representation JSON if available.
     */
    private String extractDisplayName(NormalizedEvent event) {
        if (event.getRepresentation() == null || event.getRepresentation().trim().isEmpty()) {
            return null;
        }
        
        try {
            com.fasterxml.jackson.databind.JsonNode repNode = JsonUtil.parseJson(event.getRepresentation());
            if (repNode != null && repNode.isObject()) {
                // For USER resources, try username or email
                if ("USER".equals(event.getResourceType())) {
                    if (repNode.has("username") && repNode.get("username").isTextual()) {
                        return repNode.get("username").asText();
                    }
                    if (repNode.has("email") && repNode.get("email").isTextual()) {
                        return repNode.get("email").asText();
                    }
                }
                // For CLIENT resources, try clientId
                if ("CLIENT".equals(event.getResourceType())) {
                    if (repNode.has("clientId") && repNode.get("clientId").isTextual()) {
                        return repNode.get("clientId").asText();
                    }
                }
                // Fallback to any "name" or "id" field
                if (repNode.has("name") && repNode.get("name").isTextual()) {
                    return repNode.get("name").asText();
                }
            }
        } catch (Exception e) {
            log.debug("Failed to parse representation for display name: {}", e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Maps Keycloak resource type to FHIR resource type code.
     */
    private String mapKeycloakResourceTypeToFhir(String keycloakResourceType) {
        if (keycloakResourceType == null) {
            return "Resource";
        }
        
        // Map common Keycloak resource types to FHIR resource types
        switch (keycloakResourceType.toUpperCase()) {
            case "USER":
                return "Person";
            case "CLIENT":
            case "CLIENT_SCOPE":
                return "Device";
            case "REALM":
            case "REALM_ROLE":
            case "CLIENT_ROLE":
                return "Organization";
            case "GROUP":
                return "Group";
            default:
                // For unknown types, use generic Resource
                return "Resource";
        }
    }

    private void addText(ObjectNode auditEvent, NormalizedEvent event, EventMappingLoader.EventTypeMapping mapping) {
        ObjectNode textNode = auditEvent.putObject("text");
        textNode.put("status", "generated");
        String username = event.getUsername() != null ? event.getUsername() : "unknown";
        textNode.put("div", String.format("<div>%s event for %s</div>", mapping.display(), username));
    }

    private String formatEventType(String eventType) {
        if (eventType == null) return "Unknown Event";
        return eventType.replace("_", " ")
                .toLowerCase()
                .substring(0, 1).toUpperCase()
                + eventType.replace("_", " ").toLowerCase().substring(1);
    }

}

