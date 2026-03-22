#!/usr/bin/env python3

"""Madypass - secure password generator and encrypted local vault."""

from __future__ import annotations

import json
import logging
import secrets
import string
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List

from cryptography.fernet import Fernet, InvalidToken
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

APP_NAME = "Madypass"
APP_DIR = Path.home() / ".generate-password"
LOG_DIR = APP_DIR / "log"
KEY_FILE = APP_DIR / "secret.key"
ENC_FILE = APP_DIR / "passwords.enc"
LOG_FILE = LOG_DIR / "password_generator.log"
ICON_PATH = "/usr/share/icons/hicolor/64x64/apps/madypass.png"
DEFAULT_PASSWORD_LENGTH = 16
PASSWORD_PLACEHOLDER = "Generated password will appear here"
SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
DIGITS_ONLY_LABEL = "Digits only"
MASK_CHARACTER = "•"

APP_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PasswordEntry:
    timestamp: str
    account: str
    password: str

    def serialize(self) -> str:
        return json.dumps(
            {
                "timestamp": self.timestamp,
                "account": self.account,
                "password": self.password,
            },
            ensure_ascii=False,
        )

    @classmethod
    def from_serialized(cls, value: str) -> "PasswordEntry | None":
        raw_value = value.rstrip("\n")

        try:
            payload = json.loads(raw_value)
        except json.JSONDecodeError:
            payload = None

        if isinstance(payload, dict):
            timestamp = str(payload.get("timestamp", "")).strip()
            account = str(payload.get("account", "")).strip()
            password = str(payload.get("password", ""))
            if timestamp and account and password:
                return cls(timestamp=timestamp, account=account, password=password)

        legacy_parts = raw_value.split(" | ", maxsplit=2)
        if len(legacy_parts) != 3:
            return None
        return cls(*legacy_parts)

    @property
    def masked_password(self) -> str:
        return MASK_CHARACTER * max(8, len(self.password))


class PasswordStore:
    def __init__(self, key_file: Path, data_file: Path):
        self.key_file = key_file
        self.data_file = data_file
        self.fernet = Fernet(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        if not self.key_file.exists():
            key = Fernet.generate_key()
            self.key_file.write_bytes(key)
            logger.info("Secret key created")
            return key

        logger.info("Secret key loaded")
        return self.key_file.read_bytes()

    def save_entry(self, account: str, password: str) -> PasswordEntry:
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        entry = PasswordEntry(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            account=account,
            password=password,
        )
        encrypted = self.fernet.encrypt(entry.serialize().encode("utf-8"))
        with self.data_file.open("ab") as file_handle:
            file_handle.write(encrypted + b"\n")
        logger.info("Password saved for account: %s", account)
        return entry

    def load_entries(self) -> List[PasswordEntry]:
        if not self.data_file.exists():
            logger.warning("No encrypted password file found")
            return []

        entries: List[PasswordEntry] = []
        with self.data_file.open("rb") as file_handle:
            for line_number, encrypted_line in enumerate(file_handle, start=1):
                stripped_line = encrypted_line.strip()
                if not stripped_line:
                    continue
                try:
                    decrypted = self.fernet.decrypt(stripped_line).decode("utf-8")
                except InvalidToken:
                    logger.exception("Unable to decrypt line %s", line_number)
                    continue

                entry = PasswordEntry.from_serialized(decrypted)
                if entry is None:
                    logger.warning("Skipping malformed entry on line %s", line_number)
                    continue
                entries.append(entry)

        return entries

    def overwrite_entries(self, entries: Iterable[PasswordEntry]) -> None:
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        with self.data_file.open("wb") as file_handle:
            for entry in entries:
                encrypted = self.fernet.encrypt(entry.serialize().encode("utf-8"))
                file_handle.write(encrypted + b"\n")
        logger.info("Encrypted password store updated")


class PasswordGeneratorApp(QWidget):
    def __init__(self, store: PasswordStore):
        super().__init__()
        self.store = store
        self.entries: List[PasswordEntry] = []
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(QIcon(ICON_PATH))
        self.init_ui()

    def init_ui(self) -> None:
        self.resize(1000, 700)
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Account name:"))
        self.account_input = QLineEdit()
        layout.addWidget(self.account_input)

        layout.addWidget(QLabel("Password length:"))
        self.length_input = QSpinBox()
        self.length_input.setRange(4, 128)
        self.length_input.setValue(DEFAULT_PASSWORD_LENGTH)
        layout.addWidget(self.length_input)

        self.chk_uppercase = QCheckBox("Include uppercase letters")
        self.chk_uppercase.setChecked(True)
        layout.addWidget(self.chk_uppercase)

        self.chk_numbers = QCheckBox("Include numbers")
        self.chk_numbers.setChecked(True)
        layout.addWidget(self.chk_numbers)

        self.chk_special = QCheckBox("Include special characters")
        self.chk_special.setChecked(True)
        layout.addWidget(self.chk_special)

        self.chk_digits_only = QCheckBox(DIGITS_ONLY_LABEL)
        self.chk_digits_only.toggled.connect(self.toggle_digits_only_mode)
        layout.addWidget(self.chk_digits_only)

        self.result_label = QLabel(PASSWORD_PLACEHOLDER)
        self.result_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.result_label)

        self.btn_generate = QPushButton("Generate password")
        self.btn_generate.clicked.connect(self.generate_password)
        layout.addWidget(self.btn_generate)

        self.btn_copy = QPushButton("📋 Copy to clipboard")
        self.btn_copy.clicked.connect(self.copy_password)
        layout.addWidget(self.btn_copy)

        self.btn_save = QPushButton("Save password")
        self.btn_save.clicked.connect(self.save_password)
        layout.addWidget(self.btn_save)

        self.btn_read = QPushButton("📂 Show saved passwords")
        self.btn_read.clicked.connect(self.show_saved_passwords)
        layout.addWidget(self.btn_read)

        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(3)
        self.table_widget.setHorizontalHeaderLabels(["Timestamp", "Account", "Password"])
        self.table_widget.horizontalHeader().setStretchLastSection(True)
        self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_widget.cellDoubleClicked.connect(self.copy_password_from_table)
        layout.addWidget(self.table_widget)

        self.btn_delete_selected = QPushButton("❌ Delete selected")
        self.btn_delete_selected.clicked.connect(self.delete_selected_password)
        layout.addWidget(self.btn_delete_selected)

        self.setLayout(layout)

    def toggle_digits_only_mode(self, checked: bool) -> None:
        for checkbox in (self.chk_uppercase, self.chk_numbers, self.chk_special):
            checkbox.setEnabled(not checked)
            if checked:
                checkbox.setChecked(False)

    def build_charset(self) -> str:
        if self.chk_digits_only.isChecked():
            return string.digits

        charset = string.ascii_lowercase
        if self.chk_uppercase.isChecked():
            charset += string.ascii_uppercase
        if self.chk_numbers.isChecked():
            charset += string.digits
        if self.chk_special.isChecked():
            charset += SPECIAL_CHARACTERS
        return charset

    def generate_password(self) -> None:
        charset = self.build_charset()
        if not charset:
            QMessageBox.warning(self, "Error", "Select at least one character category.")
            return

        password = "".join(secrets.choice(charset) for _ in range(self.length_input.value()))
        logger.info("Password generated for account: %s", self.account_input.text().strip() or "<empty>")
        self.result_label.setText(password)

    def current_password(self) -> str:
        password = self.result_label.text().strip()
        return "" if password == PASSWORD_PLACEHOLDER else password

    def copy_password(self) -> None:
        password = self.current_password()
        if not password:
            QMessageBox.warning(self, "Error", "No password available to copy.")
            return

        QApplication.clipboard().setText(password)
        logger.info("Password copied to clipboard")
        QMessageBox.information(self, "Copied", "Password copied to clipboard.")

    def save_password(self) -> None:
        account_name = self.account_input.text().strip()
        password = self.current_password()
        if not account_name or not password:
            QMessageBox.warning(self, "Error", "Enter an account name and generate a password before saving.")
            return

        try:
            saved_entry = self.store.save_entry(account_name, password)
        except OSError:
            logger.exception("Unable to save password for account: %s", account_name)
            QMessageBox.critical(self, "Save error", "Unable to write the encrypted password file.")
            return

        self.entries.append(saved_entry)
        self.refresh_password_table()
        QMessageBox.information(self, "Saved", "Password encrypted and saved successfully.")

    def refresh_password_table(self) -> None:
        self.table_widget.setRowCount(len(self.entries))
        for row_index, entry in enumerate(self.entries):
            values = (entry.timestamp, entry.account, entry.masked_password)
            for column_index, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column_index == 2:
                    item.setTextAlignment(Qt.AlignCenter)
                self.table_widget.setItem(row_index, column_index, item)

    def show_saved_passwords(self) -> None:
        self.entries = self.store.load_entries()
        self.refresh_password_table()
        logger.info("Saved passwords loaded into table")

    def delete_selected_password(self) -> None:
        row = self.table_widget.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Error", "Select a row to delete.")
            return
        if row >= len(self.entries):
            QMessageBox.warning(self, "Error", "Unable to match the selected row with a stored password.")
            return

        del self.entries[row]
        self.store.overwrite_entries(self.entries)
        self.show_saved_passwords()
        logger.info("Password at row %s deleted", row)
        QMessageBox.information(self, "Deleted", "Password deleted successfully.")

    def copy_password_from_table(self, row: int, _column: int) -> None:
        if row < 0 or row >= len(self.entries):
            return

        password = self.entries[row].password
        QApplication.clipboard().setText(password)
        logger.info("Password copied from row %s", row)
        QMessageBox.information(self, "Copied", "Password copied to clipboard.")


def main() -> None:
    app = QApplication([])
    app.setStyleSheet(
        """
        QWidget { background-color: #2b2b2b; color: white; font-family: Consolas; }
        QLabel { font-size: 14px; color: white; }
        QLineEdit, QSpinBox, QTableWidget, QTableWidgetItem {
            background-color: #3c3f41; color: white; border: 1px solid #555;
        }
        QPushButton {
            background-color: #44475a; color: white;
            border: 1px solid #6272a4; padding: 5px; font-weight: bold;
        }
        QPushButton:hover { background-color: #6272a4; }
        """
    )
    window = PasswordGeneratorApp(PasswordStore(KEY_FILE, ENC_FILE))
    window.show()
    app.exec_()


if __name__ == "__main__":
    main()
