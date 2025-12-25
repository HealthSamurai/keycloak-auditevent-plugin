package io.healthsamurai.keycloak.auditevent.builder;

import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

/**
 * Loads event mappings from YAML configuration file.
 */
public class EventMappingLoader {

    private static final Logger log = LoggerFactory.getLogger(EventMappingLoader.class);
    private static final String MAPPINGS_FILE = "/event-mappings.yaml";

    /**
     * Loads event type mappings from YAML file.
     *
     * @return Map of event type to EventTypeMapping
     */
    public static Map<String, EventTypeMapping> loadEventMappings() {
        Map<String, EventTypeMapping> mappings = new HashMap<>();

        try (InputStream inputStream = EventMappingLoader.class.getResourceAsStream(MAPPINGS_FILE)) {
            if (inputStream == null) {
                log.warn("Event mappings file {} not found, using empty mappings", MAPPINGS_FILE);
                return mappings;
            }

            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(inputStream);

            // Load variables first
            Map<String, String> variables = loadVariables(data);

            @SuppressWarnings("unchecked")
            Map<String, Map<String, Object>> eventMappings =
                    (Map<String, Map<String, Object>>) data.get("eventMappings");

            if (eventMappings != null) {
                for (Map.Entry<String, Map<String, Object>> entry : eventMappings.entrySet()) {
                    String eventType = entry.getKey();
                    Map<String, Object> mappingData = entry.getValue();

                    String code = replaceVariables((String) mappingData.get("code"), variables);
                    String display = replaceVariables((String) mappingData.get("display"), variables);
                    String action = replaceVariables((String) mappingData.get("action"), variables);
                    String outcome = replaceVariables((String) mappingData.get("outcome"), variables);

                    SubtypeMapping subtype = null;
                    @SuppressWarnings("unchecked")
                    Map<String, Object> subtypeMap = (Map<String, Object>) mappingData.get("subtype");
                    if (subtypeMap != null) {
                        String subtypeSystem = replaceVariables((String) subtypeMap.get("system"), variables);
                        String subtypeCode = replaceVariables((String) subtypeMap.get("code"), variables);
                        String subtypeDisplay = replaceVariables((String) subtypeMap.get("display"), variables);
                        subtype = new SubtypeMapping(subtypeSystem, subtypeCode, subtypeDisplay);
                    }

                    mappings.put(eventType, new EventTypeMapping(code, display, action, outcome, subtype));
                }
                log.info("Loaded {} event type mappings from YAML", mappings.size());
            }
        } catch (Exception e) {
            log.error("Failed to load event mappings from YAML file: {}", e.getMessage(), e);
        }

        return mappings;
    }

    /**
     * Returns the set of supported event types defined in YAML.
     */
    public static Set<String> loadSupportedEventTypes() {
        return new HashSet<>(loadEventMappings().keySet());
    }

    /**
     * Loads default mapping from YAML file.
     *
     * @return Default EventTypeMapping
     */
    public static EventTypeMapping loadDefaultMapping() {
        try (InputStream inputStream = EventMappingLoader.class.getResourceAsStream(MAPPINGS_FILE)) {
            if (inputStream == null) {
                log.warn("Event mappings file {} not found, using hardcoded default", MAPPINGS_FILE);
                return new EventTypeMapping("110100", "Application Activity", "E", "0", null);
            }

            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(inputStream);

            // Load variables first
            Map<String, String> variables = loadVariables(data);

            @SuppressWarnings("unchecked")
            Map<String, Object> defaultMapping = (Map<String, Object>) data.get("defaultMapping");

            if (defaultMapping != null) {
                String code = replaceVariables((String) defaultMapping.get("code"), variables);
                String display = replaceVariables((String) defaultMapping.get("display"), variables);
                String action = replaceVariables((String) defaultMapping.get("action"), variables);
                String outcome = replaceVariables((String) defaultMapping.get("outcome"), variables);

                SubtypeMapping subtype = null;
                @SuppressWarnings("unchecked")
                Map<String, Object> subtypeMap = (Map<String, Object>) defaultMapping.get("subtype");
                if (subtypeMap != null) {
                    String subtypeSystem = replaceVariables((String) subtypeMap.get("system"), variables);
                    String subtypeCode = replaceVariables((String) subtypeMap.get("code"), variables);
                    String subtypeDisplay = replaceVariables((String) subtypeMap.get("display"), variables);
                    subtype = new SubtypeMapping(subtypeSystem, subtypeCode, subtypeDisplay);
                }

                return new EventTypeMapping(code, display, action, outcome, subtype);
            }
        } catch (Exception e) {
            log.error("Failed to load default mapping from YAML file: {}", e.getMessage(), e);
        }

        return new EventTypeMapping("110100", "Application Activity", "E", "0", null);
    }

    /**
     * Loads variables from the 'values' section in YAML.
     *
     * @param data The parsed YAML data
     * @return Map of variable names to their values
     */
    private static Map<String, String> loadVariables(Map<String, Object> data) {
        Map<String, String> variables = new HashMap<>();

        @SuppressWarnings("unchecked")
        Map<String, Object> valuesMap = (Map<String, Object>) data.get("values");

        if (valuesMap != null) {
            for (Map.Entry<String, Object> entry : valuesMap.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                if (value != null) {
                    variables.put(key, value.toString());
                }
            }
            log.debug("Loaded {} variables from YAML", variables.size());
        }

        return variables;
    }

    /**
     * Replaces variable references (e.g., $dicom) with their actual values.
     *
     * @param str The string that may contain variable references
     * @param variables Map of variable names to values
     * @return String with variables replaced, or original string if no variables found
     */
    private static String replaceVariables(String str, Map<String, String> variables) {
        if (str == null || str.isEmpty() || variables.isEmpty()) {
            return str;
        }

        String result = str;
        for (Map.Entry<String, String> entry : variables.entrySet()) {
            String varName = entry.getKey();
            String varValue = entry.getValue();
            // Replace $variableName with actual value
            result = result.replace("$" + varName, varValue);
        }

        return result;
    }

    // Helper classes for mappings (same as in AuditEventBuilder)
    public record EventTypeMapping(String code, String display, String action, String outcome, SubtypeMapping subtype) {}
    public record SubtypeMapping(String system, String code, String display) {}
}

