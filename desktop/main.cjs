const { app, BrowserWindow, dialog } = require("electron");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

let panel;

async function createWindow() {
  const panelModule = pathToFileURL(path.join(__dirname, "..", "dist", "panel.js")).href;
  const { startPanel } = await import(panelModule);
  panel = await startPanel({
    cwd: process.cwd(),
    port: 0,
    allowedRoots: [path.parse(process.cwd()).root],
    reportsDir: path.join(app.getPath("userData"), "reports"),
    openBrowser: false,
  });
  const window = new BrowserWindow({ width: 1280, height: 860, minWidth: 900, minHeight: 640, webPreferences: { contextIsolation: true, sandbox: true } });
  await window.loadURL(panel.url);
  window.on("closed", () => { panel?.close(); panel = undefined; });
}

app.whenReady().then(createWindow).catch((error) => {
  dialog.showErrorBox("LEGO Security Scanner 启动失败", error instanceof Error ? error.message : String(error));
  app.quit();
});
app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
app.on("before-quit", () => { panel?.close(); });
