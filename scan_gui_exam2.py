import sys
import subprocess
import re
import threading
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QTextEdit, QMessageBox, QSplashScreen,QComboBox,
    QProgressBar, QFileDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer
from PyQt5.QtGui import QPixmap, QMovie, QFont, QIcon, QPalette, QColor

output_lines = []
process = None

def run_openssl_connect(host):
    cmd = [
        "openssl", "s_client",
        "-connect", host,
        "-servername", host.split(":")[0],
        "-ign_eof",
        "-state",
        "-msg"
    ]
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output_lines = []

        def monitor():
            for line in process.stdout:
                output_lines.append(line)
                if "read R BLOCK" in line:
                    process.terminate()
                    break

        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.start()
        monitor_thread.join(timeout=30)

        if monitor_thread.is_alive():
            process.kill()
            monitor_thread.join()

        output = ''.join(output_lines)
        if not output.strip():
            return None, "No output received from OpenSSL"
        return output, None

    except subprocess.TimeoutExpired:
        return None, "Connection timed out"
    except Exception as e:
        return None, str(e)


def extract_ssl_details(output):
    cert_data = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", output, re.DOTALL)
    subject = re.search(r"subject=([^\n\r]+)", output)
    issuer = re.search(r"issuer=([^\n\r]+)", output)
    verify_result = re.search(r"Verify return code: (\d+) \((.*?)\)", output)
    protocol = re.search(r"Protocol\s*:\s*(.*?)\n", output)
    cipher = re.search(r"Cipher\s*:\s*(.*?)\n", output)
    group = re.search(r"Negotiated TLS1\.3 group:\s*([^\n\r]+)", output) or re.search(r"Server Temp Key:\s*([^\n\r]+)", output)
    group = group.group(1).strip() if group else "Unknown"
    pkey_line = re.search(r"a:PKEY:\s*([A-Z0-9\-]+),\s*(\d+)\s*\(bit\);", output)
    if pkey_line:
        public_key = f"{pkey_line.group(2)} bit {pkey_line.group(1)}"
    else:
        pubkey = re.search(r"Server public key is\s+(\d+ bit)", output)
        if pubkey:
            peer_sig_type = re.search(r"Peer signature type:\s*([a-zA-Z0-9_]+)", output)
            if peer_sig_type:
                algo = peer_sig_type.group(1).replace("_", "-")
                public_key = f"{pubkey.group(1)} ({algo})"
            else:
                public_key = pubkey.group(1)
        else:
            public_key = "Unknown"
    alpn = re.search(r"ALPN protocol:\s*(.*?)\n", output)
    resumed = re.search(r"(New|Reused), TLSv1\.3", output)
    resumed_status = resumed.group(1) if resumed else "Unknown"
    signature_algo = re.search(r"sigalg:\s*(.*?)\n", output)
    return {
        "certificate": cert_data[0] if cert_data else None,
        "subject": subject.group(1).strip() if subject else "N/A",
        "issuer": issuer.group(1).strip() if issuer else "N/A",
        "verify_result": verify_result.groups() if verify_result else ("?", "Unknown"),
        "protocol": protocol.group(1).strip() if protocol else "Unknown",
        "cipher": cipher.group(1).strip() if cipher else "Unknown",
        "group": group,
        "public_key": public_key,
        "alpn": alpn.group(1).strip() if alpn else "None",
        "resumed": resumed_status,
        "signature_algo": signature_algo.group(1).strip() if signature_algo else "Unknown",
    }

class ScanThread(QThread):
    result_signal = pyqtSignal(object, object)
    def __init__(self, host):
        super().__init__()
        self.host = host
    def run(self):
        output, error = run_openssl_connect(self.host)
        self.result_signal.emit(output, error)

class SSLGui(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OpenSSL TLS Session Inspector - PTPKM")
        self.resize(800, 700)
        self.setStyleSheet("background-color: #f0f4f7;")
        self.setFont(QFont("Segoe UI", 10))
        self.dark_mode = False
        self.init_ui()

    def toggle_theme(self):
        if self.dark_mode:
            self.setStyleSheet("background-color: #f0f4f7; color: black;")
        else:
            self.setStyleSheet("background-color: #1e1e1e; color: #eee;")
        self.dark_mode = not self.dark_mode

    def init_ui(self):
        layout = QVBoxLayout()

        logo_layout = QHBoxLayout()
        self.logo_label = QLabel()
        pixmap = QPixmap("LOGO PTPKM blk-02.png")
        if not pixmap.isNull():
            self.logo_label.setPixmap(pixmap.scaled(QSize(70, 70), Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            self.logo_label.setText("🔐")
            self.logo_label.setFont(QFont("Arial", 36, QFont.Bold))
        header = QHBoxLayout()
        header.addWidget(self.logo_label)
        header.addWidget(QLabel("<h2 style='color:#005f99;'>TLS Scanner - PTPKM</h2>"))
        header.addStretch()
        header.addWidget(QLabel("© 2025 PTPKM"))
        layout.addLayout(header)

        input_layout = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText("example: ptpkm.gov.my:443")
        self.input.setStyleSheet("QLineEdit { padding: 6px; border: 1px solid #ccc; border-radius: 8px; }")
        self.dropdown = QComboBox()
        self.dropdown.addItems(["mcmc.gov.my:443", "google.com:443", "cloudflare.com:443"])
        self.dropdown.currentIndexChanged.connect(lambda: self.input.setText(self.dropdown.currentText()))
        self.scan_btn = QPushButton("🔍Scan")
        self.scan_btn.setIcon(QIcon("search_icon.png"))
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #007acc; color: white; border-radius: 10px; padding: 6px 14px;
            }
            QPushButton:hover {
                background-color: #005f99;
            }
        """)
        self.scan_btn.clicked.connect(self.scan)
        self.toggle_btn = QPushButton("🌙 Toggle Dark Mode")
        self.toggle_btn.clicked.connect(self.toggle_theme)
        input_layout.addWidget(QLabel("Domain/IP:Port"))
        input_layout.addWidget(self.input)
        input_layout.addWidget(self.dropdown)
        input_layout.addWidget(self.scan_btn)
        input_layout.addWidget(self.toggle_btn)
        layout.addLayout(input_layout)

        self.status = QLabel("Enter a domain and port to begin scan.")
        layout.addWidget(self.status)

        self.progress = QProgressBar()
        self.progress.setMaximum(0)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.table = QTableWidget(7, 2)
        self.table.setHorizontalHeaderLabels(["Parameter", "Value"])
        self.table.setVerticalHeaderLabels([
            "Protocol Version", "Cipher Suite", "Key Exchange Group",
            "Public Key", "ALPN Protocol", "Session Resumed", "Signature Algorithm"
        ])
        self.table.verticalHeader().setVisible(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        self.cert_table = QTableWidget(3, 2)
        self.cert_table.setHorizontalHeaderLabels(["Field", "Details"])
        self.cert_table.setVerticalHeaderLabels(["Subject", "Issuer", "Verify Code"])
        self.cert_table.verticalHeader().setVisible(True)
        self.cert_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.cert_table)

        layout.addWidget(QLabel("Server Certificate (PEM)"))
        self.cert_text = QTextEdit()
        self.cert_text.setReadOnly(True)
        layout.addWidget(self.cert_text)

        save_btn = QPushButton("💾 Save Certificate")
        save_btn.clicked.connect(self.save_certificate)
        layout.addWidget(save_btn)

        self.setLayout(layout)

    def save_certificate(self):
        pem = self.cert_text.toPlainText()
        if not pem.strip():
            QMessageBox.warning(self, "No Certificate", "No certificate data to save.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save PEM", "", "PEM Files (*.pem);;All Files (*)")
        if path:
            with open(path, "w") as f:
                f.write(pem)
            QMessageBox.information(self, "Saved", f"Certificate saved to:\n{path}")

    def scan(self):
        host = self.input.text().strip()
        if ":" not in host:
            QMessageBox.warning(self, "Input Error", "Please include domain/IP and port, e.g., ptpkm.gov.my:443")
            return
        self.status.setText("Scanning...")
        self.table.clearContents()
        self.cert_table.clearContents()
        self.cert_text.clear()
        self.progress.setVisible(True)
        self.scan_btn.setEnabled(False)
        QApplication.processEvents()
        self.thread = ScanThread(host)
        self.thread.result_signal.connect(self.show_result)
        self.thread.start()

    def show_result(self, output, error):
        self.progress.setVisible(False)
        self.scan_btn.setEnabled(True)
        if error:
            self.status.setText(f"Error: {error}")
            QMessageBox.critical(self, "Scan Error", error)
            return
        info = extract_ssl_details(output)
        params = [
            info["protocol"], info["cipher"], info["group"], info["public_key"],
            info["alpn"], info["resumed"], info["signature_algo"]
        ]
        for i, val in enumerate(params):
            self.table.setItem(i, 0, QTableWidgetItem(self.table.verticalHeaderItem(i).text()))
            self.table.setItem(i, 1, QTableWidgetItem(val))
        self.cert_table.setItem(0, 0, QTableWidgetItem("Subject"))
        self.cert_table.setItem(0, 1, QTableWidgetItem(info["subject"]))
        self.cert_table.setItem(1, 0, QTableWidgetItem("Issuer"))
        self.cert_table.setItem(1, 1, QTableWidgetItem(info["issuer"]))
        self.cert_table.setItem(2, 0, QTableWidgetItem("Verify Code"))
        self.cert_table.setItem(2, 1, QTableWidgetItem(f"{info['verify_result'][0]} ({info['verify_result'][1]})"))
        if info["certificate"]:
            self.cert_text.setPlainText(f"-----BEGIN CERTIFICATE-----{info['certificate']}-----END CERTIFICATE-----")
        else:
            self.cert_text.setPlainText("(No certificate found)")
        self.status.setText("Scan complete.")

def main():
    app = QApplication(sys.argv)
    splash = QSplashScreen(QPixmap("LOGO PTPKM blk-02.png"))
    splash.showMessage("Loading TLS Scanner...", Qt.AlignHCenter | Qt.AlignBottom, Qt.white)
    splash.show()
    QTimer.singleShot(800, splash.close)
    gui = SSLGui()
    QTimer.singleShot(900, gui.show)
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
