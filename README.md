# Keycloak FHIR AuditEvent Plugin

A Keycloak SPI plugin that converts user and admin events to FHIR R4 AuditEvents and sends them to any FHIR server.

## Features

- ✅ Converts Keycloak authentication events (LOGIN, LOGOUT, LOGIN_ERROR, etc.) to FHIR R4 AuditEvents
- ✅ Supports admin events (CREATE, UPDATE, DELETE, ACTION operations)
- ✅ Configurable via environment variables or system properties
- ✅ Multiple authentication methods: none, Basic Auth, Bearer Token, **Keycloak Internal**
- ✅ Asynchronous event sending (configurable)
- ✅ Debug mode for troubleshooting
- ✅ Standards-compliant FHIR R4 AuditEvent resources
- ✅ Native Keycloak 26 token generation (no HTTP, no reflection)

## Requirements

- Java 17+
- Keycloak 26.0.0+
- Maven 3.6+ (for building)

## Building

```bash
mvn clean package
```

The plugin JAR will be created at `target/keycloak-fhir-auditevent-plugin-0.2.0.jar`

## Installation

1. Copy the JAR file to your Keycloak `providers` directory:
   ```bash
   cp target/keycloak-fhir-auditevent-plugin-0.2.0.jar $KEYCLOAK_HOME/providers/
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
| `FHIR_AUTH_TYPE` | Authentication type: `none`, `basic`, `bearer`, `keycloak` | `none` |
| `FHIR_AUTH_USERNAME` | Username for Basic Auth | - |
| `FHIR_AUTH_PASSWORD` | Password for Basic Auth | - |
| `FHIR_AUTH_TOKEN` | Bearer token for Bearer Auth | - |
| `KEYCLOAK_CLIENT_ID` | Client ID for Keycloak internal auth (service account) | - |
| `KEYCLOAK_REALM` | Realm name for Keycloak internal auth | `master` |
| `FHIR_ADMIN_EVENTS_ENABLED` | Enable admin events processing | `false` |
| `FHIR_ASYNC_ENABLED` | Enable asynchronous sending | `true` |
| `FHIR_DEBUG_ENABLED` | Enable debug logging | `false` |

### Authentication Methods

#### 1. No Authentication
```bash
export FHIR_AUTH_TYPE="none"
```

#### 2. Basic Authentication
```bash
export FHIR_AUTH_TYPE="basic"
export FHIR_AUTH_USERNAME="your-username"
export FHIR_AUTH_PASSWORD="your-password"
```

#### 3. Bearer Token (Static)
```bash
export FHIR_AUTH_TYPE="bearer"
export FHIR_AUTH_TOKEN="your-static-token"
```

#### 4. Keycloak Internal Authentication (Recommended)

This method uses Keycloak's native API to generate JWT tokens internally **without HTTP requests**. Perfect for FHIR servers protected by the same Keycloak instance.

**Setup Requirements:**
1. Create a client in Keycloak with:
   - **Service Account Enabled** = ON
   - **Client Authentication** = ON
   - Assign required roles to the service account user

2. Configure environment variables:
```bash
export FHIR_AUTH_TYPE="keycloak"
export KEYCLOAK_CLIENT_ID="your-service-account-client"
export KEYCLOAK_REALM="your-realm"  # Optional, defaults to "master"
```

**How it works:**
- Plugin creates JWT tokens using Keycloak's internal session API
- Tokens are signed with the realm's RSA private key
- No HTTP requests or client secrets needed
- Tokens are generated on-demand for each FHIR request
- Uses native Keycloak 26 API (no reflection, no external calls)

**Example:**
```bash
export FHIR_SERVER_URL="http://fhir-server:8080/fhir/AuditEvent"
export FHIR_AUTH_TYPE="keycloak"
export KEYCLOAK_CLIENT_ID="fhir-audit-client"
export KEYCLOAK_REALM="healthcare"
export FHIR_ADMIN_EVENTS_ENABLED="true"
export FHIR_DEBUG_ENABLED="false"
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
