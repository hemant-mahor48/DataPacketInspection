const state = {
    livePollingHandle: null
};

const uploadForm = document.getElementById("upload-form");
const firewallForm = document.getElementById("firewall-form");
const historyFilterForm = document.getElementById("history-filter-form");
const pcapFileInput = document.getElementById("pcap-file");
const firewallFileInput = document.getElementById("firewall-file");
const interfaceSelect = document.getElementById("interface-select");
const feedback = document.getElementById("feedback");
const liveIndicator = document.getElementById("live-indicator");
const sourceLabel = document.getElementById("source-label");
const recordsBody = document.getElementById("records-body");
const notesList = document.getElementById("notes-list");
const sessionList = document.getElementById("session-list");
const browserActivityList = document.getElementById("browser-activity-list");
const trendChart = document.getElementById("trend-chart");

document.getElementById("refresh-interfaces").addEventListener("click", loadInterfaces);
document.getElementById("start-live").addEventListener("click", startLiveCapture);
document.getElementById("stop-live").addEventListener("click", stopLiveCapture);
document.getElementById("load-latest-history").addEventListener("click", loadLatestHistory);
uploadForm.addEventListener("submit", submitUpload);
firewallForm.addEventListener("submit", uploadFirewallLog);
historyFilterForm.addEventListener("submit", applyHistoryFilters);

window.addEventListener("load", async () => {
    await loadInterfaces();
    await refreshLiveStatus();
    await Promise.all([loadSessions(), loadBrowserActivity(), loadTrends(), loadLatestHistory()]);
});

async function loadInterfaces() {
    try {
        const interfaces = await fetchJson("/api/interfaces");
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
        const snapshot = await fetchMultipart("/api/upload", formData);
        renderSnapshot(snapshot);
        await loadSessions();
        await loadTrends();
        showFeedback("PCAP analysis completed and saved to history.", "success");
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

async function uploadFirewallLog(event) {
    event.preventDefault();
    if (!firewallFileInput.files.length) {
        showFeedback("Choose a firewall log file to import.", "error");
        return;
    }

    const formData = new FormData();
    formData.append("file", firewallFileInput.files[0]);

    try {
        const message = await fetchMultipart("/api/history/firewall/upload", formData, false);
        showFeedback(message, "success");
        await loadLatestHistory();
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
        const snapshot = await fetchJson("/api/live/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interfaceName: interfaceSelect.value })
        });
        renderSnapshot(snapshot);
        ensurePolling();
        showFeedback("Live capture started.", "success");
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

async function stopLiveCapture() {
    try {
        const snapshot = await fetchJson("/api/live/stop", { method: "POST" });
        renderSnapshot(snapshot);
        stopPollingIfIdle(snapshot);
        await loadSessions();
        await loadTrends();
        showFeedback("Live capture stopped and session history saved.", "success");
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

async function refreshLiveStatus() {
    try {
        const snapshot = await fetchJson("/api/live/status");
        renderSnapshot(snapshot);
        if (snapshot.liveRunning) {
            ensurePolling();
        }
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

async function applyHistoryFilters(event) {
    event.preventDefault();
    const params = new URLSearchParams({
        ip: document.getElementById("filter-ip").value,
        protocol: document.getElementById("filter-protocol").value,
        decision: document.getElementById("filter-decision").value,
        host: document.getElementById("filter-host").value,
        service: document.getElementById("filter-service").value,
        limit: "200"
    });

    try {
        const records = await fetchJson(`/api/history/records?${params.toString()}`);
        renderRecords(records);
        showFeedback(`Loaded ${records.length} filtered history records.`, "success");
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

async function loadLatestHistory() {
    try {
        const records = await fetchJson("/api/history/records?limit=100");
        renderRecords(records);
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

async function loadSessions() {
    try {
        const sessions = await fetchJson("/api/history/sessions");
        sessionList.innerHTML = "";
        if (!sessions.length) {
            sessionList.innerHTML = "<li>No sessions saved yet.</li>";
            return;
        }
        sessions.forEach((session) => {
            const item = document.createElement("li");
            item.innerHTML = `<strong>${session.sessionType}</strong> | ${session.sourceName} | ${session.packetCount || 0} packets`;
            sessionList.appendChild(item);
        });
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

async function loadBrowserActivity() {
    try {
        const activities = await fetchJson("/api/history/browser-activity");
        browserActivityList.innerHTML = "";
        if (!activities.length) {
            browserActivityList.innerHTML = "<li>No browser activity captured yet.</li>";
            return;
        }
        activities.forEach((activity) => {
            const item = document.createElement("li");
            item.innerHTML = `<strong>${activity.serviceName || activity.browserName}</strong> | ${activity.pageTitle} <span class="muted-inline">${activity.hostname || ""}</span>`;
            browserActivityList.appendChild(item);
        });
    } catch (error) {
        showFeedback(error.message, "error");
    }
}

async function loadTrends() {
    try {
        const points = await fetchJson("/api/history/trends?minutes=180");
        renderTrendChart(points);
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
            const snapshot = await fetchJson("/api/live/status");
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

function renderTrendChart(points) {
    trendChart.innerHTML = "";
    if (!points.length) {
        trendChart.innerHTML = '<p class="empty-state">No persisted trend data yet.</p>';
        return;
    }

    const maxValue = Math.max(...points.map((point) => point.totalPackets || 0), 1);
    points.slice(-18).forEach((point) => {
        const bar = document.createElement("div");
        bar.className = "trend-bar";
        bar.innerHTML = `
            <span>${point.bucketLabel}</span>
            <div class="trend-bar-track">
                <div class="trend-bar-fill" style="width:${Math.max(8, ((point.totalPackets || 0) / maxValue) * 100)}%"></div>
            </div>
            <strong>${point.totalPackets || 0}</strong>
        `;
        trendChart.appendChild(bar);
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

async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    if (!response.ok) {
        throw new Error(await response.text());
    }
    return response.json();
}

async function fetchMultipart(url, formData, expectJson = true) {
    const response = await fetch(url, {
        method: "POST",
        body: formData
    });
    if (!response.ok) {
        throw new Error(await response.text());
    }
    return expectJson ? response.json() : response.text();
}

function showFeedback(message, type) {
    feedback.textContent = message;
    feedback.className = `feedback ${type}`;
}
