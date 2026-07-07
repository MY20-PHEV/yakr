"""Toga UI shell for the Yakr Android reference client."""

from __future__ import annotations

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW


class YakrMobileApp(toga.App):
    def startup(self) -> None:
        self.main_box = toga.Box(style=Pack(direction=COLUMN, padding=10))
        self.contact_list = toga.Selection(items=[], style=Pack(flex=1, padding_bottom=8))
        self.chat_log = toga.MultilineTextInput(readonly=True, style=Pack(flex=1, height=200))
        self.message_input = toga.TextInput(placeholder="Message", style=Pack(flex=1))
        send_button = toga.Button("Send", on_press=self.on_send, style=Pack(padding_left=8))
        fetch_button = toga.Button("Fetch", on_press=self.on_fetch, style=Pack(padding_top=8))
        invite_button = toga.Button("Show Invite QR", on_press=self.on_invite, style=Pack(padding_top=8))

        input_row = toga.Box(style=Pack(direction=ROW))
        input_row.add(self.message_input)
        input_row.add(send_button)

        self.main_box.add(self.contact_list)
        self.main_box.add(self.chat_log)
        self.main_box.add(input_row)
        self.main_box.add(fetch_button)
        self.main_box.add(invite_button)

        self.main_window = toga.MainWindow(title=self.formal_name)
        self.main_window.content = self.main_box
        self.main_window.show()
        self._refresh_contacts()

    def _client(self):
        from pathlib import Path

        from yakr_mobile.client import YakrMobileClient
        from yakr_mobile.encrypted_store import MobileStore

        data_dir = Path(self.paths.data) / "yakr"
        store = MobileStore(data_dir / "mobile.db", passphrase="yakr-mobile-dev")
        relay_url = "http://10.0.2.2:8080"
        return YakrMobileClient(store, relay_url=relay_url)

    def _refresh_contacts(self) -> None:
        client = self._client()
        self.contact_list.items = client.store.list_contacts() or ["(no contacts)"]

    def on_send(self, widget) -> None:
        contact = str(self.contact_list.value)
        if contact.startswith("("):
            return
        result = self._client().send_text(contact, self.message_input.value)
        self.chat_log.value += f"\nYou: {self.message_input.value} (seq={result.seq})"
        self.message_input.value = ""

    def on_fetch(self, widget) -> None:
        contact = str(self.contact_list.value)
        if contact.startswith("("):
            return
        fetched = self._client().fetch_contact(contact)
        for message in fetched.messages:
            self.chat_log.value += f"\n{contact}: {message}"

    def on_invite(self, widget) -> None:
        presentation = self._client().create_invite(rendezvous_hint="http://127.0.0.1:8090")
        self.chat_log.value += f"\nInvite safety code: {presentation.safety}"
        self.chat_log.value += f"\nInvite URL: {presentation.url[:48]}…"


def main() -> YakrMobileApp:
    return YakrMobileApp(formal_name="Yakr", app_id="sh.yakr.mobile")
