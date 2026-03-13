const state = {
    livePollingHandle: null
};

const uploadForm = document.getElementById("upload-form");
const pcapFileInput = document.getElementById("pcap-file");
const interfaceSelect = document.getElementById("interface-select");
const feedback = document.getElementById("feedback");
const liveIndicator = document.getElementById("live-indicator");
const sourceLabel = document.getElementById("source-label");
const recordsBody = document.getElementById("records-body");
const notesList = document.getElementById("notes-list");

document.getElementById("refresh-interfaces").addEventListener("click", loadInterfaces);
document.getElementById("start-live").addEventListener("click", startLiveCapture);
document.getElementById("stop-live").addEventListener("click", stopLiveCapture);
uploadForm.addEventListener("submit", submitUpload);

window.addEventListener("load", async () => {
    await loadInterfaces();
    await refreshLiveStatus();
});

async function loadInterfaces() {
    try {
        const response = await fetch("/api/interfaces");
        if (!response.ok) {
            throw new Error(await response.text());
        }

        const interfaces = await response.json();
        interfaceSelect.innerHTML = "";

        if (!interfaces.length) {
            interfaceSelect.innerHTML = `<option value="">No interfaces detected</option>`;
            return;
        }

        interfaces.forEach((item) => {
            const option = document.createElement("option");
            const addresses = item.addresses?.length ? ` [${item.addresses.join(", ")}]` : "";
            option.value = item.name;
            option.textContent = `${item.name}${item.description ? ` - ${item.description}` : ""}${addresses}`;
            interfaceSelect.appendChild(option);
        });
        showFeedback("Network interfaces refreshed.", "success");
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

async function submitUpload(event) {
    event.preventDefault();

    if (!pcapFileInput.files.length) {
        showFeedback("Please choose a PCAP file first.", "error");
        return;
    }

    const formData = new FormData();
    formData.append("file", pcapFileInput.files[0]);

    try {
        showFeedback("Analyzing uploaded capture...", "success");
        const response = await fetch("/api/upload", {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            throw new Error(await response.text());
        }

        const snapshot = await response.json();
        renderSnapshot(snapshot);
        showFeedback("PCAP analysis completed successfully.", "success");
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

async function startLiveCapture() {
    if (!interfaceSelect.value) {
        showFeedback("Please select a network interface.", "error");
        return;
    }

    try {
        const response = await fetch("/api/live/start", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ interfaceName: interfaceSelect.value })
        });

        if (!response.ok) {
            throw new Error(await response.text());
        }

        const snapshot = await response.json();
        renderSnapshot(snapshot);
        ensurePolling();
        showFeedback("Live capture started.", "success");
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

async function stopLiveCapture() {
    try {
        const response = await fetch("/api/live/stop", { method: "POST" });
        if (!response.ok) {
            throw new Error(await response.text());
        }

        const snapshot = await response.json();
        renderSnapshot(snapshot);
        stopPollingIfIdle(snapshot);
        showFeedback("Live capture stopped.", "success");
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

async function refreshLiveStatus() {
    try {
        const response = await fetch("/api/live/status");
        if (!response.ok) {
            throw new Error(await response.text());
        }
        const snapshot = await response.json();
        renderSnapshot(snapshot);
        if (snapshot.liveRunning) {
            ensurePolling();
        }
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

function ensurePolling() {
    if (state.livePollingHandle) {
        return;
    }
    state.livePollingHandle = setInterval(async () => {
        try {
            const response = await fetch("/api/live/status");
            if (!response.ok) {
                throw new Error(await response.text());
            }
            const snapshot = await response.json();
            renderSnapshot(snapshot);
            stopPollingIfIdle(snapshot);
        } catch (error) {
            showFeedback(error.message, "error");
            clearInterval(state.livePollingHandle);
            state.livePollingHandle = null;
        }
    }, 2500);
}

function stopPollingIfIdle(snapshot) {
    if (!snapshot.liveRunning && state.livePollingHandle) {
        clearInterval(state.livePollingHandle);
        state.livePollingHandle = null;
    }
}

function renderSnapshot(snapshot) {
    sourceLabel.textContent = `${snapshot.sourceName || "Unknown source"}${snapshot.selectedInterface ? ` | ${snapshot.selectedInterface}` : ""}`;
    liveIndicator.textContent = snapshot.liveRunning ? "Live capture running" : "Live capture stopped";
    liveIndicator.className = `indicator ${snapshot.liveRunning ? "indicator-on" : "indicator-off"}`;

    updateStat("totalPackets", snapshot.stats?.totalPackets);
    updateStat("allowedPackets", snapshot.stats?.allowedPackets);
    updateStat("blockedPackets", snapshot.stats?.blockedPackets);
    updateStat("reviewPackets", snapshot.stats?.reviewPackets);
    updateStat("tcpPackets", snapshot.stats?.tcpPackets);
    updateStat("udpPackets", snapshot.stats?.udpPackets);
    updateStat("icmpPackets", snapshot.stats?.icmpPackets);
    updateStat("dnsPackets", snapshot.stats?.dnsPackets);
    updateStat("httpPackets", snapshot.stats?.httpPackets);
    updateStat("httpsPackets", snapshot.stats?.httpsPackets);

    renderNotes(snapshot.notes || []);
    renderRecords(snapshot.records || []);
}

function renderNotes(notes) {
    notesList.innerHTML = "";
    if (!notes.length) {
        notesList.innerHTML = "<li>No analysis notes yet.</li>";
        return;
    }

    notes.forEach((note) => {
        const item = document.createElement("li");
        item.textContent = note;
        notesList.appendChild(item);
    });
}

function renderRecords(records) {
    recordsBody.innerHTML = "";
    if (!records.length) {
        recordsBody.innerHTML = `<tr><td colspan="11" class="empty-state">No packet events available yet.</td></tr>`;
        return;
    }

    records.forEach((record) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${formatTimestamp(record.timestamp)}</td>
            <td>${record.sourceIp || "Unknown"}</td>
            <td>${record.destinationIp || "Unknown"}</td>
            <td>${record.protocol || "Unknown"}</td>
            <td>${formatPorts(record.sourcePort, record.destinationPort)}</td>
            <td>${record.applicationHint || "Unknown"}</td>
            <td>${record.detectedHost || "-"}</td>
            <td>${record.hostSource || "-"}</td>
            <td>${record.serviceName || "Unknown Service"}</td>
            <td><span class="decision-pill ${decisionClass(record.decision)}">${record.decision || "REVIEW"}</span></td>
            <td>${record.reason || ""}</td>
        `;
        recordsBody.appendChild(row);
    });
}

function updateStat(id, value) {
    document.getElementById(id).textContent = value ?? 0;
}

function formatTimestamp(value) {
    if (!value) {
        return "Unknown";
    }
    return new Date(value).toLocaleString();
}

function formatPorts(sourcePort, destinationPort) {
    if (sourcePort == null && destinationPort == null) {
        return "-";
    }
    return `${sourcePort ?? "-"} -> ${destinationPort ?? "-"}`;
}

function decisionClass(decision) {
    if (decision === "ALLOWED") {
        return "decision-allowed";
    }
    if (decision === "BLOCKED") {
        return "decision-blocked";
    }
    return "decision-review";
}

function showFeedback(message, type) {
    feedback.textContent = message;
    feedback.className = `feedback ${type}`;
}
