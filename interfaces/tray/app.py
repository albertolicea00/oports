"""Native system tray entry point and scan coordination."""

import sys

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon

from core.local_ports import get_local_ports
from core.scanner import scan_network
from interfaces.desktop.app import DeviceWindow


class ScanThread(QThread):
    results = Signal(object, str, object)
    failed = Signal(str)

    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface

    def run(self):
        try:
            devices, subnet = scan_network(self.interface)
            self.results.emit(devices, subnet, get_local_ports())
        except Exception as exc:
            self.failed.emit(str(exc))


def app_icon():
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor("#1677c8"))
    painter.drawRoundedRect(5, 5, 54, 54, 14, 14)
    painter.setPen(QPen(QColor("white"), 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    painter.drawArc(16, 16, 32, 32, 20 * 16, 140 * 16)
    painter.drawArc(23, 23, 18, 18, 20 * 16, 140 * 16)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor("white"))
    painter.drawEllipse(29, 39, 6, 6)
    painter.end()
    return QIcon(pixmap)


class OPortsApplication:
    def __init__(self, mode="desktop", interface=None):
        self.app = QApplication.instance() or QApplication(sys.argv[:1])
        self.app.setApplicationName("OPorts")
        self.app.setQuitOnLastWindowClosed(False)
        self.interface = interface
        self.worker = None
        self.window = DeviceWindow(self.refresh)
        self.window.on_close = self.quit
        icon = app_icon()
        self.app.setWindowIcon(icon)
        self.window.setWindowIcon(icon)
        app_menu = self.window.menuBar().addMenu("File")
        app_menu.addAction("Refresh", self.refresh)
        app_menu.addAction("Hide Window", self.window.hide)
        app_menu.addAction("Quit", self.quit)

        self.tray = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(icon, self.window)
            self.menu = QMenu()
            self.summary = self.menu.addAction("OPorts — scanning…")
            self.summary.setEnabled(False)
            self.menu.addSeparator()
            self.menu.addAction("Open OPorts", self.show_window)
            self.menu.addAction("Refresh", self.refresh)
            self.menu.addSeparator()
            self.menu.addAction("Quit", self.quit)
            self.tray.setContextMenu(self.menu)
            self.tray.setToolTip("OPorts")
            self.tray.activated.connect(self._activated)
            self.tray.show()
            self.window.minimize_to_tray = True
        if mode == "tray" and self.tray is None:
            self.window.status.setText("System tray unavailable; showing the desktop window")
        if mode == "desktop" or self.tray is None:
            self.window.show()
        QTimer.singleShot(0, self.refresh)

    def _activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self.show_window()

    def show_window(self):
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def refresh(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.window.set_loading()
        if self.tray:
            self.summary.setText("OPorts — scanning…")
        self.worker = ScanThread(self.interface)
        self.worker.results.connect(self._show_results)
        self.worker.failed.connect(self._show_error)
        self.worker.start()

    def _show_results(self, devices, subnet, ports):
        self.window.set_results(devices, subnet, ports)
        if self.tray:
            label = "{} devices · {} local ports".format(len(devices), len(ports))
            self.summary.setText(label)
            self.tray.setToolTip("OPorts — " + label)

    def _show_error(self, message):
        self.window.set_error(message)
        if self.tray:
            self.summary.setText("OPorts — scan failed")

    def quit(self):
        self.window.allow_close = True
        if self.tray:
            self.tray.hide()
        self.window.hide()
        if self.worker and self.worker.isRunning():
            self.worker.finished.connect(self.app.quit)
        else:
            self.app.quit()

    def run(self):
        return self.app.exec()


def main(mode="desktop", interface=None):
    return OPortsApplication(mode=mode, interface=interface).run()


def tray_main():
    return main(mode="tray")
