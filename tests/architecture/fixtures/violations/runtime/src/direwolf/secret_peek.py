"""Violation fixture (M4e, TX027 and TX031): the runtime reaching a keychain
and asking for a value."""

import keyring


def credential_read(handle: str) -> str | None:
    return keyring.get_password("direwolf", handle)


def get_secret(handle: str) -> str | None:
    return credential_read(handle)
