# DataPacketInspection

DataPacketInspection is a Spring Boot network-inspection platform that now supports:

- offline PCAP upload analysis
- real-time packet capture
- persistent history storage
- filtering by IP, protocol, decision, host, and service
- trend charts from stored packet history
- firewall-log correlation for stronger blocked-request detection
- browser-agent integration for exact page titles and active-tab URLs
- authentication and role-based access

## What was added

### Persistent storage

The app now stores:

- uploaded capture sessions
- live capture sessions
- packet events for each session
- imported firewall log entries
- browser activity events

By default, the app uses a file-based H2 database for easy local startup.
For production-style persistence, PostgreSQL and MySQL profiles are included.

Files:
- [application.properties](/H:/DataPacketInspection/src/main/resources/application.properties)
- [application-postgres.properties](/H:/DataPacketInspection/src/main/resources/application-postgres.properties)
- [application-mysql.properties](/H:/DataPacketInspection/src/main/resources/application-mysql.properties)

### Search and analytics

The dashboard now includes:

- history filters for IP, protocol, decision, host, and service
- saved capture sessions
- traffic trend bars from persisted history
- recent browser activity view

### Firewall log integration

You can upload Windows Firewall log files and the backend will parse `DROP` entries.
Those events are used to improve blocked-request classification when packet traffic matches the imported firewall evidence.

### Browser agent

A Chrome-compatible extension scaffold is included in:

- [manifest.json](/H:/DataPacketInspection/src/main/resources/browser-agent/manifest.json)
- [background.js](/H:/DataPacketInspection/src/main/resources/browser-agent/background.js)
- [popup.html](/H:/DataPacketInspection/src/main/resources/browser-agent/popup.html)

It sends:

- page title
- page URL
- browser name
- tab and window identifiers

To the backend endpoint:

- `POST /api/browser-agent/activity`

using the header:

- `X-Agent-Token`

Default token:

- `browser-agent-demo-token`

Change it with:

- `AGENT_TOKEN`

### Authentication and roles

Spring Security is enabled with role-based access.

Default demo users:

- `admin / admin123` -> roles `ADMIN`, `ANALYST`
- `analyst / analyst123` -> role `ANALYST`

Access model:

- dashboard and packet APIs require `ANALYST`
- firewall-log upload requires `ADMIN`
- browser-agent ingestion uses the shared agent token instead of user login

Security config:

- [SecurityConfig.java](/H:/DataPacketInspection/src/main/java/com/datapacketinspection/config/SecurityConfig.java)

## Main backend components

- packet parsing and domain/service inference: [PacketInspectionService.java](/H:/DataPacketInspection/src/main/java/com/datapacketinspection/service/PacketInspectionService.java)
- live capture and live-session persistence: [LiveCaptureService.java](/H:/DataPacketInspection/src/main/java/com/datapacketinspection/service/LiveCaptureService.java)
- persisted history, filters, and trend building: [HistoryService.java](/H:/DataPacketInspection/src/main/java/com/datapacketinspection/service/HistoryService.java)
- firewall log import and correlation: [FirewallLogService.java](/H:/DataPacketInspection/src/main/java/com/datapacketinspection/service/FirewallLogService.java)
- browser activity ingestion: [BrowserActivityService.java](/H:/DataPacketInspection/src/main/java/com/datapacketinspection/service/BrowserActivityService.java)

## Dashboard files

- UI template: [dashboard.html](/H:/DataPacketInspection/src/main/resources/templates/dashboard.html)
- frontend logic: [app.js](/H:/DataPacketInspection/src/main/resources/static/js/app.js)
- styling: [app.css](/H:/DataPacketInspection/src/main/resources/static/css/app.css)

## Running with the default local database

```bash
mvn spring-boot:run
```

Then open:

- [http://localhost:8080](http://localhost:8080)

### H2 console

- [http://localhost:8080/h2-console](http://localhost:8080/h2-console)

Default JDBC URL:

```text
jdbc:h2:file:./data/datapacketinspection;MODE=PostgreSQL;AUTO_SERVER=TRUE
```

## Running with PostgreSQL

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=postgres
```

Or set:

- `DATABASE_URL`
- `DATABASE_USERNAME`
- `DATABASE_PASSWORD`

## Running with MySQL

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=mysql
```

Or set:

- `DATABASE_URL`
- `DATABASE_USERNAME`
- `DATABASE_PASSWORD`

## API overview

### Core traffic APIs

- `POST /api/upload`
- `GET /api/interfaces`
- `POST /api/live/start`
- `POST /api/live/stop`
- `GET /api/live/status`

### History APIs

- `GET /api/history/sessions`
- `GET /api/history/records`
- `GET /api/history/trends`
- `GET /api/history/browser-activity`
- `GET /api/history/firewall-events`
- `POST /api/history/firewall/upload`

### Browser agent API

- `POST /api/browser-agent/activity`

## Current limitations

- Packet inspection can often identify services and domains, but not exact encrypted content.
- Exact YouTube video names or Instagram post content still require browser-aware telemetry, which is why the browser-agent integration was added.
- Firewall correlation is currently based on imported log matching, not deep OS event subscription.
- Authentication is implemented with in-memory users for simplicity; a persistent user store would be a strong next step.

## Suggested next step

The strongest follow-up would be to replace in-memory auth with database-backed users and add alerting rules on top of the stored history.
