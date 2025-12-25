package io.healthsamurai.keycloak.auditevent.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Utility class for JSON operations using Jackson.
 */
public final class JsonUtil {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

    private JsonUtil() {
        // Utility class
    }

    /**
     * Creates a new empty ObjectNode.
     *
     * @return A new ObjectNode
     */
    public static ObjectNode createObjectNode() {
        return OBJECT_MAPPER.createObjectNode();
    }

    /**
     * Converts an object to JSON string.
     *
     * @param object The object to serialize
     * @return JSON string
     * @throws JsonProcessingException if serialization fails
     */
    public static String toJson(Object object) throws JsonProcessingException {
        return OBJECT_MAPPER.writeValueAsString(object);
    }

    /**
     * Converts an object to pretty-printed JSON string.
     * Uses Jackson's default pretty printer with 2-space indentation.
     *
     * @param object The object to serialize
     * @return Pretty-printed JSON string
     * @throws JsonProcessingException if serialization fails
     */
    public static String toPrettyJson(Object object) throws JsonProcessingException {
        return OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(object);
    }

    /**
     * Parses a JSON string into a JsonNode.
     *
     * @param json JSON string
     * @return JsonNode or null if parsing fails
     */
    public static JsonNode parseJson(String json) {
        if (json == null || json.trim().isEmpty()) {
            return null;
        }
        try {
            return OBJECT_MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            return null;
        }
    }
}

