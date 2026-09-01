import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

Item {
  id: root

  property var settings: ({})
  property var status: Model.emptyStatus()
  property bool daemonReachable: false
  property string lastError: ""
  property bool setupBusy: false
  property bool startBusy: false

  readonly property string pluginDir: {
    var url = Qt.resolvedUrl(".")
    return String(url).replace(/^file:\/\//, "").replace(/\/$/, "")
  }
  readonly property string serverPath: pluginDir + "/daemon/iphone-camera-server.py"
  readonly property string setupDevicePath: pluginDir + "/setup-device"
  readonly property string rootSetupPath: "/usr/local/lib/omarchy-iphone-camera/setup-device"
  readonly property string statusPath: (Quickshell.env("XDG_RUNTIME_DIR") || ("/run/user/" + Quickshell.env("UID"))) + "/omarchy-iphone-camera/status.json"
  readonly property bool running: daemonReachable && status.running
  readonly property bool streaming: running && status.streaming
  readonly property bool needsDevice: !status.deviceReady
  readonly property bool busy: startBusy || setupBusy || commandProcess.running

  function refresh() {
    statusFile.reload()
    unitProc.running = false
    unitProc.running = true
  }

  function applyRaw(raw) {
    var parsed = Model.parseStatus(raw)
    daemonReachable = parsed.ok && parsed.running
    status = parsed
    if (parsed.error) lastError = parsed.error
    else if (daemonReachable) lastError = ""
  }

  function stateGone() {
    daemonReachable = false
    status = Model.emptyStatus()
  }

  function sendCtl(verb) {
    commandProcess.command = ["python3", serverPath, "ctl", verb]
    commandProcess.running = true
  }

  function startDaemon() {
    startBusy = true
    lastError = ""
    startProc.command = ["bash", "-lc",
      "python3 " + quote(serverPath) + " install-unit >/dev/null && systemctl --user enable --now omarchy-iphone-camera.service"]
    startProc.running = true
  }

  function stopDaemon() {
    startBusy = true
    stopProc.command = ["systemctl", "--user", "stop", "omarchy-iphone-camera.service"]
    stopProc.running = true
  }

  function toggleDaemon() {
    if (running) stopDaemon()
    else startDaemon()
  }

  function rotateToken() { sendCtl("rotate-token") }
  function stopStream() { sendCtl("stop-stream") }

  function setupDevice() {
    setupBusy = true
    lastError = ""
    var helper = rootSetupPath
    setupProc.command = ["bash", "-lc",
      "helper=" + quote(setupDevicePath) + "; " +
      "[ -x /usr/local/lib/omarchy-iphone-camera/setup-device ] && helper=/usr/local/lib/omarchy-iphone-camera/setup-device; " +
      "if sudo -n true 2>/dev/null; then sudo \"$helper\" install; else pkexec \"$helper\" install; fi"]
    setupProc.running = true
  }

  function copyUrl() {
    var url = status.pairUrl
    if (!url) return
    Quickshell.execDetached(["wl-copy", url])
  }

  function quote(s) {
    return "'" + String(s).replace(/'/g, "'\\''") + "'"
  }

  FileView {
    id: statusFile
    path: root.statusPath
    watchChanges: true
    printErrors: false
    onFileChanged: reload()
    onLoaded: root.applyRaw(text())
    onLoadFailed: root.stateGone()
  }

  Process {
    id: commandProcess
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: if (text) root.applyRaw(text)
    }
  }

  Process {
    id: startProc
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: if (text) root.lastError = String(text).trim()
    }
    onExited: function (code) {
      root.startBusy = false
      if (code !== 0 && !root.lastError) root.lastError = "Could not start the camera daemon"
      Qt.callLater(root.refresh)
    }
  }

  Process {
    id: stopProc
    onExited: function () {
      root.startBusy = false
      root.stateGone()
      Qt.callLater(root.refresh)
    }
  }

  Process {
    id: setupProc
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: if (text) root.lastError = String(text).trim()
    }
    onExited: function (code) {
      root.setupBusy = false
      if (code !== 0 && !root.lastError) root.lastError = "Virtual camera setup failed or was cancelled"
      Qt.callLater(root.refresh)
    }
  }

  Process {
    id: unitProc
    command: ["systemctl", "--user", "is-active", "omarchy-iphone-camera.service"]
    stdout: StdioCollector { waitForEnd: true }
  }

  Timer {
    interval: 1500
    running: true
    repeat: true
    onTriggered: {
      statusFile.reload()
    }
  }

  Component.onCompleted: refresh()
}
