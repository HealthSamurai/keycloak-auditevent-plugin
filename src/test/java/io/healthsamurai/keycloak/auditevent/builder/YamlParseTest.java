package io.healthsamurai.keycloak.auditevent.builder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;

public class YamlParseTest {

    @Test
    void testSimpleYamlParse() throws Exception {
        String yaml = "resourceType: AuditEvent\n" +
                     "id: test-123\n" +
                     "action: E";

        ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
        JsonNode node = yamlMapper.readTree(yaml);

        System.out.println("Parsed YAML:");
        System.out.println(node.toPrettyString());
    }

    @Test
    void testYamlWithTemplateOutput() throws Exception {
        // Test parsing YAML with template-like structure
        String yaml = "resourceType: AuditEvent\n" +
                     "id: abc-123\n" +
                     "outcome: 0\n" +
                     "recorded: 2023-11-14T22:13:20Z";

        ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
        JsonNode node = yamlMapper.readTree(yaml);

        System.out.println("Parsed YAML:");
        System.out.println(node.toPrettyString());
    }
}
