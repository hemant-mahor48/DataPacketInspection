const CONFIG = {
  endpoint: "http://localhost:8080/api/browser-agent/activity",
  token: "browser-agent-demo-token"
};

chrome.tabs.onActivated.addListener(async () => {
  await publishActiveTab();
});

chrome.tabs.onUpdated.addListener(async (_tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.active) {
    await publishTab(tab);
  }
});

async function publishActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (tabs.length) {
    await publishTab(tabs[0]);
  }
}

async function publishTab(tab) {
  if (!tab || !tab.url || !tab.title) {
    return;
  }

  try {
    await fetch(CONFIG.endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Agent-Token": CONFIG.token
      },
      body: JSON.stringify({
        browserName: "Chrome",
        pageTitle: tab.title,
        pageUrl: tab.url,
        tabId: String(tab.id || ""),
        windowId: String(tab.windowId || "")
      })
    });
  } catch (error) {
    console.error("Failed to send browser activity", error);
  }
}
