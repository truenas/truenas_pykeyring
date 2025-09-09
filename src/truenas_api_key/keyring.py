import truenas_keyring
from dataclasses import asdict
from json import dumps, loads
from datetime import datetime, timezone
from .constants import KEYRING_NAME, UserApiKey


"""
Below is a rough diagram of how these are organized:

  Persistent Keyring (for UID 0)
  └── TRUENAS_API_KEYS
      ├── username_1/
      │   ├── API Key (dbid: 123)
      │   ├── API Key (dbid: 124)
      │   └── ...
      ├── username_2/
      │   ├── API Key (dbid: 456)
      │   ├── API Key (dbid: 457)
      │   └── ...
      └── ...

This module assumes that middlewared and the process
calling into PAM will be running as UID 0 and therefore
have a shared persistent keyring.
"""


def get_api_keyring():
    persistent_keyring = truenas_keyring.get_persistent_keyring()
    try:
        api_key_keyring = persistent_keyring.search(
            key_type=truenas_keyring.KeyType.KEYRING,
            description=KEYRING_NAME
        )
    except FileNotFoundError:
        api_key_keyring = truenas_keyring.add_keyring(
            description=KEYRING_NAME,
            target_keyring=persistent_keyring.key.serial
        )

    return api_key_keyring


def get_user_keyring(username: str):
    keyring = get_api_keyring()

    try:
        user_ring = keyring.search(
            key_type=truenas_keyring.KeyType.KEYRING, description=username
        )
    except FileNotFoundError:
        # most likely explanation is key ring doesn't exist
        user_ring = truenas_keyring.add_keyring(
            description=username,
            target_keyring=keyring.key.serial
        )

    return user_ring


def commit_user_entry(username: str, api_keys: list[UserApiKey]) -> None:
    """ Creates or replaces existing user keyring with new one containing only
    the API keys specified by `api_keys`"""
    user_ring = get_user_keyring(username)
    # Clear out existing keyring. We'll replace with new entries
    user_ring.clear()

    for entry in api_keys:
        # Skip revoked entries
        if entry.expiry == -1:
            continue

        # Skip expired entries
        if entry.expiry > 0:
            now = datetime.now(timezone.utc)
            expiry_time = datetime.fromtimestamp(entry.expiry, timezone.utc)
            if expiry_time <= now:
                continue

        key = truenas_keyring.add_key(
            key_type=truenas_keyring.KeyType.USER,
            description=str(entry.dbid),
            data=dumps(asdict(entry)).encode(),
            target_keyring=user_ring.key.serial
        )

        # Apply timeout if expiry is set (> 0)
        if entry.expiry > 0:
            timeout_seconds = int((expiry_time - now).total_seconds())
            key.set_timeout(timeout=timeout_seconds)


def clear_all_api_keys() -> None:
    """ Clear out all user api keys in the truenas api key keyring """
    get_api_keyring().clear()


def clear_user_keyring(username: str) -> None:
    """ Clear all keys in user keyring """
    user_ring = get_user_keyring(username)
    # Clear out existing keyring. We'll replace with new entries
    user_ring.clear()


def dump_user_keyring(username: str) -> list:
    """ dump user API key keyring contents """
    user_ring = get_user_keyring(username)
    out = []

    for entry in user_ring.list_keyring_contents():
        data = entry.read_data()
        out.append(loads(data.decode()))

    return out
