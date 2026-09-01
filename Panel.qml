import QtQuick
import Quickshell
import qs.Commons
import qs.Ui
import "Model.js" as Model

Panel {
  id: root
  moduleName: "io.github.boraoku.ioscam"
  ipcTarget: "io.github.boraoku.ioscam"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root
  readonly property bool streaming: cam.streaming
  readonly property bool running: cam.running

  function toggleDaemon() { cam.toggleDaemon() }
  function refreshDaemon() { cam.refresh() }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function")
      return root.bar.switchPanelFrom(root.barIdentity, direction)
    return false
  }

  property int cursorIndex: 0
  property bool cursorActive: false
  property int qrRev: 0
  property int phraseIndex: 0
  property string lastPairUrl: ""
  property int previewShow: 0
  property string previewSrc0: ""
  property string previewSrc1: ""
  readonly property string runtimeDir: (Quickshell.env("XDG_RUNTIME_DIR") || "/run/user/1000") + "/omarchy-iphone-camera"

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property color hoverFill: bar ? Style.hoverFillFor(bar.foreground, Color.accent) : "transparent"
  readonly property color selectedFill: bar ? Style.selectedFillFor(bar.foreground, Color.accent) : "transparent"
  readonly property color barIconColor: cam.streaming ? barForeground : (cam.running ? barForeground : Qt.darker(barForeground, 1.55))

  readonly property var activePhrases: [
    "Continuity, but Linux",
    "Propping up the phone",
    "Waiting in the wings",
    "Framing the shot",
    "Lighting the subject",
    "Holding the pose",
    "Keeping Safari awake",
    "Borrowing the lens"
  ]
  readonly property string heroPhraseText: cam.streaming
    ? Model.heroMeta(cam.status)
    : (cam.running ? activePhrases[phraseIndex % activePhrases.length] : "Turned off")

  readonly property var cursorRows: {
    var rows = ["power"]
    if (cam.needsDevice) rows.push("setup")
    if (cam.running) {
      rows.push("copy")
      rows.push("rotate")
    }
    if (cam.streaming) rows.push("stop")
    return rows
  }

  readonly property string cursorRow: cursorRows.length === 0
    ? ""
    : cursorRows[Math.max(0, Math.min(cursorIndex, cursorRows.length - 1))]

  function rowHasCursor(name) {
    return cursorActive && cursorRow === name
  }

  function moveCursor(dy) {
    cursorActive = true
    if (cursorRows.length === 0) return
    cursorIndex = Math.max(0, Math.min(cursorRows.length - 1, cursorIndex + dy))
  }

  function activateCursor() {
    var name = cursorRow
    if (name === "power") cam.toggleDaemon()
    else if (name === "setup") cam.setupDevice()
    else if (name === "copy") cam.copyUrl()
    else if (name === "rotate") cam.rotateToken()
    else if (name === "stop") cam.stopStream()
  }

  function focusRow(name) {
    var at = cursorRows.indexOf(name)
    if (at < 0) return
    cursorActive = true
    cursorIndex = at
  }

  onOpenedChanged: if (opened) {
    cursorActive = false
    cursorIndex = 0
    cam.refresh()
    qrRev++
    Qt.callLater(function () { keyCatcher.forceActiveFocus() })
  }

  Service {
    id: cam
  }

  Timer {
    interval: 2800
    running: root.opened && cam.running && !cam.streaming
    repeat: true
    onTriggered: root.phraseIndex = (root.phraseIndex + 1) % root.activePhrases.length
  }

  Timer {
    interval: 180
    running: root.opened && cam.streaming
    repeat: true
    onTriggered: {
      var next = 1 - root.previewShow
      var path = root.runtimeDir + "/preview-" + next + ".jpg"
      var src = "file://" + path + "?t=" + Date.now()
      if (next === 0) root.previewSrc0 = src
      else root.previewSrc1 = src
    }
  }

  Connections {
    target: cam
    function onStatusChanged() {
      if (cam.status.pairUrl !== root.lastPairUrl) {
        root.lastPairUrl = cam.status.pairUrl
        root.qrRev++
      }
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.hostWidget || root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(380))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(640))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onMoveRequested: function (dx, dy) {
        if (!root.cursorActive) { root.cursorActive = true; return }
        if (dy !== 0) root.moveCursor(dy)
      }
      onActivateRequested: if (root.cursorActive) root.activateCursor()
      onCloseRequested: root.close()
      onTabRequested: function (direction) { root.switchPanel(direction) }
      onTextKey: function (t) {
        var key = String(t).toLowerCase()
        if (key === "r") cam.refresh()
        else if (key === "n") cam.rotateToken()
        else if (key === "c") cam.copyUrl()
        else if (key === "s") cam.setupDevice()
        else if (key === " ") cam.toggleDaemon()
      }

      Column {
        id: column
        width: parent.width
        spacing: Style.space(14)

        PanelHero {
          title: "iPhone Camera"
          meta: root.heroPhraseText
          detail: cam.streaming ? "LIVE" : (cam.status.deviceReady ? "" : "SETUP")
          foreground: root.foreground
          fontFamily: root.fontFamily
          iconOpacity: cam.running ? 1.0 : 0.5
          iconComponent: Component {
            Text {
              textFormat: Text.PlainText
              text: "󰄀"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.display
            }
          }
          trailingControl: Component {
            ToggleSwitch {
              checked: cam.running
              busy: cam.startBusy
              hasCursor: root.rowHasCursor("power")
              foreground: root.foreground
              onHovered: function (on) { if (on) root.focusRow("power") }
              onToggled: cam.toggleDaemon()
            }
          }
        }

        PanelSeparator { foreground: root.foreground }

        Column {
          visible: cam.needsDevice
          width: parent.width
          spacing: Style.space(10)

          Text {
            width: parent.width
            textFormat: Text.PlainText
            wrapMode: Text.WordWrap
            text: "Create a virtual webcam named iPhone Camera so Zoom, Meet, and OBS can pick it."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }

          Button {
            width: parent.width
            text: cam.setupBusy ? "Setting up…" : "Set up virtual camera"
            foreground: root.foreground
            fontFamily: root.fontFamily
            bordered: true
            hasCursor: root.rowHasCursor("setup")
            enabled: !cam.setupBusy
            onHovered: function (on) { if (on) root.focusRow("setup") }
            onClicked: cam.setupDevice()
          }
        }

        Column {
          visible: cam.running
          width: parent.width
          spacing: Style.space(10)

          PanelSectionHeader {
            text: cam.streaming ? "PREVIEW" : "PAIR iPHONE"
            foreground: root.foreground
            fontFamily: root.fontFamily
          }

          Rectangle {
            visible: cam.streaming
            width: parent.width
            height: Math.round(width * 9 / 16)
            radius: Style.cornerRadius
            color: "#111"
            clip: true

            Image {
              anchors.fill: parent
              source: root.previewSrc0
              cache: false
              asynchronous: true
              fillMode: Image.PreserveAspectCrop
              opacity: root.previewShow === 0 ? 1 : 0
              onStatusChanged: if (status === Image.Ready) root.previewShow = 0
            }
            Image {
              anchors.fill: parent
              source: root.previewSrc1
              cache: false
              asynchronous: true
              fillMode: Image.PreserveAspectCrop
              opacity: root.previewShow === 1 ? 1 : 0
              onStatusChanged: if (status === Image.Ready) root.previewShow = 1
            }
          }

          Item {
            visible: !cam.streaming && cam.status.qrPng !== ""
            width: parent.width
            height: qrBox.height

            Rectangle {
              id: qrBox
              width: Math.min(parent.width, Style.space(220))
              height: width
              radius: Style.cornerRadius
              color: "white"
              anchors.horizontalCenter: parent.horizontalCenter

              Image {
                anchors.fill: parent
                anchors.margins: Style.space(10)
                source: Model.fileUrl(cam.status.qrPng, root.qrRev)
                cache: false
                fillMode: Image.PreserveAspectFit
                asynchronous: true
              }
            }
          }

          Text {
            visible: !cam.streaming
            width: parent.width
            textFormat: Text.PlainText
            wrapMode: Text.WordWrap
            text: "Scan with the iPhone camera. First time only: install the trust profile, then Settings → General → About → Certificate Trust Settings → enable Omarchy iPhone Camera. Keep Safari open on the back camera."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            visible: cam.status.pairUrl !== ""
            width: parent.width
            textFormat: Text.PlainText
            wrapMode: Text.WrapAnywhere
            text: Model.shortUrl(cam.status.pairUrl)
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            visible: cam.status.iphoneUsb
            width: parent.width
            textFormat: Text.PlainText
            wrapMode: Text.WordWrap
            text: (cam.status.iphoneName || "iPhone") + " is on USB. For a wired link, enable Personal Hotspot → USB, then rescan the code."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Row {
            spacing: Style.space(8)
            Button {
              text: "Copy link"
              foreground: root.foreground
              fontFamily: root.fontFamily
              bordered: true
              hasCursor: root.rowHasCursor("copy")
              onHovered: function (on) { if (on) root.focusRow("copy") }
              onClicked: cam.copyUrl()
            }
            Button {
              text: "New code"
              foreground: root.foreground
              fontFamily: root.fontFamily
              bordered: true
              hasCursor: root.rowHasCursor("rotate")
              onHovered: function (on) { if (on) root.focusRow("rotate") }
              onClicked: cam.rotateToken()
            }
            Button {
              visible: cam.streaming
              text: "Stop"
              foreground: root.urgent
              fontFamily: root.fontFamily
              bordered: true
              hasCursor: root.rowHasCursor("stop")
              onHovered: function (on) { if (on) root.focusRow("stop") }
              onClicked: cam.stopStream()
            }
          }
        }

        Text {
          visible: !cam.running
          width: parent.width
          textFormat: Text.PlainText
          wrapMode: Text.WordWrap
          text: "Turn it on to publish a webcam named iPhone Camera, then scan the QR code from your iPhone. No App Store app — Safari uses the back camera."
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
        }

        Text {
          visible: cam.lastError !== ""
          width: parent.width
          textFormat: Text.PlainText
          wrapMode: Text.WordWrap
          text: cam.lastError
          color: root.urgent
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }
      }
    }
  }
}
