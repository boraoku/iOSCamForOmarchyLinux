.pragma library

function emptyStatus() {
  return {
    ok: false,
    running: false,
    listening: false,
    streaming: false,
    paired: false,
    camera: "back",
    device: "",
    deviceReady: false,
    needsDevice: true,
    urls: [],
    cameraUrls: [],
    pairUrl: "",
    trustUrl: "",
    qrPng: "",
    previewJpg: "",
    iphoneUsb: false,
    iphoneName: "",
    fps: 0,
    width: 0,
    height: 0,
    error: "",
    label: "iPhone Camera"
  }
}

function parseStatus(raw) {
  var text = String(raw || "").trim()
  if (!text) return emptyStatus()
  var data
  try { data = JSON.parse(text) } catch (e) { return emptyStatus() }
  if (!data || typeof data !== "object") return emptyStatus()
  var out = emptyStatus()
  out.ok = data.ok === true
  out.running = data.running === true
  out.listening = data.listening === true
  out.streaming = data.streaming === true
  out.paired = data.paired === true
  out.camera = String(data.camera || "back")
  out.device = String(data.device || "")
  out.deviceReady = data.deviceReady === true
  out.needsDevice = data.needsDevice !== false && !out.deviceReady
  out.urls = Array.isArray(data.urls) ? data.urls.map(String) : []
  out.cameraUrls = Array.isArray(data.cameraUrls) ? data.cameraUrls.map(String) : []
  out.pairUrl = String(data.pairUrl || "")
  out.trustUrl = String(data.trustUrl || "")
  out.qrPng = String(data.qrPng || "")
  out.previewJpg = String(data.previewJpg || "")
  out.iphoneUsb = data.iphoneUsb === true
  out.iphoneName = String(data.iphoneName || "")
  out.fps = Number(data.fps || 0)
  out.width = Number(data.width || 0)
  out.height = Number(data.height || 0)
  out.error = String(data.error || "")
  out.label = String(data.label || "iPhone Camera")
  return out
}

function heroMeta(status) {
  if (!status.running) return "Off"
  if (status.streaming) {
    var size = (status.width && status.height) ? (status.width + "×" + status.height + " · ") : ""
    return size + Math.round(status.fps) + " fps · live"
  }
  if (status.paired) return "Phone connected"
  return "Waiting for iPhone"
}

function fileUrl(path, rev) {
  if (!path) return ""
  var url = "file://" + path
  if (rev) url += "?r=" + rev
  return url
}

function shortUrl(url) {
  return String(url || "").replace(/^https?:\/\//, "")
}
