"""Desktop window shared by macOS and Windows."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QLabel, QMainWindow, QPushButton,
                               QSplitter, QTableWidget, QTableWidgetItem,
                               QTabWidget, QTextEdit, QVBoxLayout, QWidget)


class DeviceWindow(QMainWindow):
    def __init__(self, refresh):
        super().__init__()
        self.setWindowTitle("OPorts")
        self.resize(940, 600)
        self.refresh = refresh
        self.devices = []
        self.ports = []
        self.minimize_to_tray = False
        self.allow_close = False
        self.on_close = None

        root = QWidget()
        layout = QVBoxLayout(root)
        heading = QHBoxLayout()
        self.status = QLabel("Ready")
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        heading.addWidget(self.status, 1)
        heading.addWidget(self.refresh_button)
        layout.addLayout(heading)

        tabs = QTabWidget()
        device_panel = QSplitter()
        self.device_table = QTableWidget(0, 5)
        self.device_table.setHorizontalHeaderLabels(["IP", "Name", "Vendor", "RTT", "Open ports"])
        self.device_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.device_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.device_table.horizontalHeader().setStretchLastSection(True)
        self.device_table.itemSelectionChanged.connect(self._show_device)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a device to see its details")
        device_panel.addWidget(self.device_table)
        device_panel.addWidget(self.details)
        device_panel.setSizes([620, 300])
        tabs.addTab(device_panel, "LAN devices")

        self.port_table = QTableWidget(0, 4)
        self.port_table.setHorizontalHeaderLabels(["Port", "Process", "PID", "Address"])
        self.port_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.port_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.port_table.horizontalHeader().setStretchLastSection(True)
        tabs.addTab(self.port_table, "Local ports")
        layout.addWidget(tabs, 1)
        self.setCentralWidget(root)

    def set_loading(self):
        self.status.setText("Scanning network…")
        self.refresh_button.setEnabled(False)

    def set_results(self, devices, subnet, ports):
        self.devices, self.ports = devices, ports
        self.status.setText("{}  |  {} devices  |  {} local ports".format(subnet, len(devices), len(ports)))
        self.refresh_button.setEnabled(True)
        self.device_table.setRowCount(len(devices))
        for row, device in enumerate(devices):
            rtt = device.get("rtt")
            values = [device["ip"], device.get("name", ""), device.get("vendor", ""),
                      "{:.1f} ms".format(rtt) if rtt is not None else "–",
                      ", ".join(map(str, device.get("open_ports", [])))]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.device_table.setItem(row, column, item)
        self.device_table.resizeColumnsToContents()
        self.port_table.setRowCount(len(ports))
        for row, port in enumerate(ports):
            values = [str(port["port"]), port["process"], str(port["pid"]), port["address"]]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.port_table.setItem(row, column, item)
        self.port_table.resizeColumnsToContents()
        self.details.clear()

    def set_error(self, message):
        self.status.setText("Scan failed: " + message)
        self.refresh_button.setEnabled(True)

    def _show_device(self):
        row = self.device_table.currentRow()
        if row < 0 or row >= len(self.devices):
            return
        device = self.devices[row]
        lines = ["{} — {}".format(device["ip"], device.get("name", "")), "",
                 "MAC: " + device.get("mac", "Unknown"),
                 "Vendor: " + device.get("vendor", "Unknown"),
                 "Interface: " + device.get("interface", "Unknown"),
                 "OS hint: " + device.get("os_guess", "Unknown"),
                 "Open ports: " + (", ".join(map(str, device.get("open_ports", []))) or "None detected"),
                 "", device.get("notes", "")]
        self.details.setPlainText("\n".join(lines))

    def closeEvent(self, event):
        if self.minimize_to_tray and not self.allow_close:
            self.hide()
            event.ignore()
        elif self.on_close and not self.allow_close:
            self.on_close()
            event.ignore()
        else:
            super().closeEvent(event)
