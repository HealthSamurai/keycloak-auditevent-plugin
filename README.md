# Keycloak FHIR AuditEvent Plugin

A Keycloak SPI plugin that converts authentication and admin events to FHIR R4 AuditEvents and sends them to any FHIR server.

## Features

- ✅ Converts Keycloak authentication events (LOGIN, LOGOUT, LOGIN_ERROR, etc.) to FHIR R4 AuditEvents
- ✅ Supports admin events (CREATE, UPDATE, DELETE, ACTION operations)
- ✅ Configurable via environment variables or system properties
- ✅ Multiple authentication methods: none, Basic Auth, Bearer Token
- ✅ Asynchronous event sending (configurable)
- ✅ Debug mode for troubleshooting
- ✅ Standards-compliant FHIR R4 AuditEvent resources

## Requirements

- Java 17+
- Keycloak 26.0.0+
- Maven 3.6+ (for building)

## Building

```bash
mvn clean package
```

The plugin JAR will be created at `target/keycloak-fhir-auditevent-plugin-1.0.0.jar`

## Installation

1. Copy the JAR file to your Keycloak `providers` directory:
   ```bash
   cp target/keycloak-fhir-auditevent-plugin-1.0.0.jar $KEYCLOAK_HOME/providers/
   ```

2. Restart Keycloak

3. Enable the event listener in Keycloak Admin Console:
   - Go to **Realm Settings** → **Events**
   - Add `fhir-auditevent` to **Event Listeners**
   - (Optional) Enable **Admin Events** if you want to track admin operations

## Configuration

Configure the plugin using environment variables or system properties:

| Variable | Description | Default |
|----------|-------------|---------|
| `FHIR_SERVER_URL` | FHIR server endpoint URL | `http://fhir-server/AuditEvent` |
| `FHIR_AUTH_TYPE` | Authentication type: `none`, `basic`, `bearer` | `none` |
| `FHIR_AUTH_USERNAME` | Username for Basic Auth | - |
| `FHIR_AUTH_PASSWORD` | Password for Basic Auth | - |
| `FHIR_AUTH_TOKEN` | Bearer token for Bearer Auth | - |
| `FHIR_ADMIN_EVENTS_ENABLED` | Enable admin events processing | `false` |
| `FHIR_ASYNC_ENABLED` | Enable asynchronous sending | `true` |
| `FHIR_DEBUG_ENABLED` | Enable debug logging | `false` |

### Example Configuration

```bash
export FHIR_SERVER_URL="http://fhir-server/AuditEvent"
export FHIR_AUTH_TYPE="bearer"
export FHIR_AUTH_TOKEN="your-token-here"
export FHIR_ADMIN_EVENTS_ENABLED="true"
export FHIR_DEBUG_ENABLED="true"
```

## Supported Events

The plugin supports the following Keycloak event types (configured via `event-mappings.yaml`):

- **Authentication Events**: LOGIN, LOGOUT, LOGIN_ERROR, REGISTER, REGISTER_ERROR, UPDATE_PASSWORD, UPDATE_PASSWORD_ERROR, etc.
- **Admin Events**: CREATE, UPDATE, DELETE, ACTION operations on users, clients, realms, and other resources

## FHIR R4 Compliance

The plugin generates FHIR R4 compliant AuditEvent resources with:
- Proper type codes (DICOM and HL7 code systems)
- Action codes (Create, Read, Update, Delete, Execute)
- Outcome codes (success/failure)
- Agent information (user, system)
- Source information (Keycloak realm)
- Entity information (for admin events)

## Testing

Run the test suite:

```bash
mvn test
```

Code coverage reports are generated in `target/site/jacoco/`

## License

MIT License - see [LICENSE](LICENSE) file for details.
