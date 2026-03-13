# DataPacketInspection

DataPacketInspection is a Java Spring Boot web application that helps inspect network traffic in two ways:

1. Upload a `.pcap` or `.pcapng` file and review packet-level details.
2. Start a live background capture from a selected network interface and inspect current system traffic in near real time.

The dashboard is built to be simple to use and focuses on:

- Sender IP and receiver IP
- Protocol and port information
- Application hints such as HTTP, HTTPS, DNS, SSH, and more
- Detected hostnames from DNS, HTTP, and TLS metadata when available
- Friendly service labels such as YouTube, Instagram, Facebook/Meta, Google, and more
- Allowed, blocked, and review-required traffic classifications
- Reasons behind each classification
- Summary cards for total, TCP, UDP, ICMP, DNS, HTTP, and HTTPS traffic

## Features

### 1. Offline PCAP upload analysis

- Upload `.pcap` or `.pcapng` files from the dashboard
- Parse packets with `pcap4j`
- Display the latest packet events in a visual table
- Show packet classification reasons, such as:
  - TCP reset detected
  - ICMP destination unreachable observed
  - Destination port matches a deny list
  - Traffic appears allowed from observed protocol state
- Detect hostnames from:
  - DNS question names
  - HTTP `Host` headers
  - TLS SNI from client hello packets

### 2. Real-time packet inspection

- Discover available local capture interfaces
- Start live capture from the dashboard
- Continuously refresh the latest in-memory packet view
- See current internet activity while the app runs in the background
- Surface service/domain clues like `youtube.com`, `googlevideo.com`, or `instagram.com` when packet metadata exposes them

### 3. Dashboard UI

- Responsive single-page dashboard using Thymeleaf, CSS, and vanilla JavaScript
- Overview cards for traffic counts
- Separate actions for upload analysis and live inspection
- Notes panel for operational guidance and capture limitations
- Packet table columns for detected host, host source, and service label

## Important behavior note

Raw packet captures do not always explicitly label traffic as "blocked" or "allowed".

Because of that, this project uses observable signals and policy rules to infer decisions:

- `BLOCKED`
  - TCP reset packets
  - ICMP/ICMPv6 unreachable responses
  - Traffic targeting ports in the local deny list: `23, 69, 135, 137, 138, 139, 445, 3389`
- `ALLOWED`
  - Standard TCP or UDP traffic with no visible deny signal
- `REVIEW`
  - Non-IP or unsupported packet types
  - System-level live capture interruption records

You can easily extend this logic in [PacketInspectionService.java](/H:/DataPacketInspection/src/main/java/com/datapacketinspection/service/PacketInspectionService.java) to match your own business or security rules.

## Tech stack

- Java 17+
- Spring Boot 3
- Thymeleaf
- Maven
- pcap4j

## Project structure

```text
src
+-- main
¦   +-- java/com/datapacketinspection
¦   ¦   +-- config
¦   ¦   +-- controller
¦   ¦   +-- dto
¦   ¦   +-- model
¦   ¦   +-- service
¦   +-- resources
¦       +-- static/css
¦       +-- static/js
¦       +-- templates
+-- test
```

## Prerequisites

### Java and Maven

- Install Java 17 or later
- Install Maven 3.9+ or use your IDE Maven support

### Packet capture driver for Windows

To inspect live traffic on Windows, install **Npcap** or another WinPcap-compatible driver.

Without that driver:

- PCAP upload analysis can still work
- Live capture will not start successfully

Administrator privileges may also be required to capture traffic from some interfaces.

## How to run

### 1. Build the application

```bash
mvn clean package
```

### 2. Start the application

```bash
mvn spring-boot:run
```

Or run the packaged jar:

```bash
java -jar target/DataPacketInspection-0.0.1-SNAPSHOT.jar
```

### 3. Open the dashboard

Visit:

[http://localhost:8080](http://localhost:8080)

## How to use

### Offline PCAP mode

1. Open the dashboard.
2. In the `Offline PCAP Analysis` section, choose a `.pcap` or `.pcapng` file.
3. Click `Analyze Uploaded Capture`.
4. Review summary cards, notes, and the packet event table.

### Live capture mode

1. Open the dashboard.
2. Click `Refresh Interfaces`.
3. Select the interface that carries your internet traffic.
4. Click `Start Live Capture`.
5. Use the internet normally, for example YouTube, Instagram, Facebook, or any web application.
6. Watch the dashboard update every few seconds.
7. Click `Stop` when finished.

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/upload` | Upload and inspect a PCAP file |
| `GET` | `/api/interfaces` | List available network interfaces |
| `POST` | `/api/live/start` | Start live capture on the selected interface |
| `POST` | `/api/live/stop` | Stop live capture |
| `GET` | `/api/live/status` | Get the latest live snapshot |

### Example live start request

```json
POST /api/live/start
Content-Type: application/json

{
  "interfaceName": "\\Device\\NPF_{YOUR-INTERFACE-ID}"
}
```

## Current limitations

- The dashboard detects domains only when the packet payload exposes them through DNS, HTTP, or TLS SNI.
- HTTPS traffic is usually visible only as encrypted transport metadata, not full page content.
- Website names such as YouTube or Instagram can often be inferred, but exact actions like the specific YouTube video usually cannot be recovered from packets alone.
- QUIC and some newer protocols encrypt hostname signals more aggressively, so domain detection can be incomplete.
- Live capture stores only a recent in-memory window of traffic for dashboard responsiveness.
- Advanced firewall verdicts require integration with OS firewall logs or security tooling.

## Recommended next improvements

If you want to take this project further, a good next phase would be:

1. Add persistent storage with PostgreSQL or MySQL.
2. Save uploaded capture history and live session history.
3. Add filters by IP, protocol, decision, host, or service.
4. Add charts for traffic trends.
5. Integrate firewall logs to improve blocked-request detection.
6. Add a browser extension or desktop agent if you want exact page titles or active-tab URLs.
7. Add authentication and user roles.

## Main files

- Application entry: [DataPacketInspectionApplication.java](/H:/DataPacketInspection/src/main/java/com/datapacketinspection/DataPacketInspectionApplication.java)
- Upload and packet parsing logic: [PacketInspectionService.java](/H:/DataPacketInspection/src/main/java/com/datapacketinspection/service/PacketInspectionService.java)
- Live capture engine: [LiveCaptureService.java](/H:/DataPacketInspection/src/main/java/com/datapacketinspection/service/LiveCaptureService.java)
- REST API: [PacketApiController.java](/H:/DataPacketInspection/src/main/java/com/datapacketinspection/controller/PacketApiController.java)
- Dashboard template: [dashboard.html](/H:/DataPacketInspection/src/main/resources/templates/dashboard.html)

## Notes for you

This project is ready as a stronger starter implementation for your requirement. For enterprise-grade packet inspection, the next step is usually:

- richer protocol decoding
- interface-level access control
- persistence and audit history
- browser-aware telemetry for exact page context
- integration with firewall and IDS/IPS signals
