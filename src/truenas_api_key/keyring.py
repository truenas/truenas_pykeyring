import truenas_keyring
from dataclasses import asdict
from json import dumps, loads
from datetime import datetime, timezone
from .constants import PAM_KEYRING_NAME, PAM_API_KEY_NAME, UserApiKey


"""
Below is a rough diagram of how these are organized:

  Persistent Keyring (for UID 0)
  └── PAM_TRUENAS
      ├── username_1/
      │   ├── API_KEYS/
      │   │   ├── API Key (dbid: 123)
      │   │   ├── API Key (dbid: 124)
      │   │   └── ...
      │   ├── SESSIONS/
      │   └── FAILLOG/
      ├── username_2/
      │   ├── API_KEYS/
      │   │   ├── API Key (dbid: 456)
      │   │   ├── API Key (dbid: 457)
      │   │   └── ...
      │   ├── SESSIONS/
      │   └── FAILLOG/
      └── ...

This module assumes that middlewared and the process
calling into PAM will be running as UID 0 and therefore
have a shared persistent keyring.
"""


def get_pam_keyring():
    persistent_keyring = truenas_keyring.get_persistent_keyring()
    try:
        pam_keyring = persistent_keyring.search(
            key_type=truenas_keyring.KeyType.KEYRING,
            description=PAM_KEYRING_NAME
        )
    except FileNotFoundError:
        pam_keyring = truenas_keyring.add_keyring(
            description=PAM_KEYRING_NAME,
            target_keyring=persistent_keyring.key.serial
        )

    return pam_keyring


def get_user_keyring(username: str):
    pam_keyring = get_pam_keyring()

    try:
        user_ring = pam_keyring.search(
            key_type=truenas_keyring.KeyType.KEYRING, description=username
        )
    except FileNotFoundError:
        # most likely explanation is key ring doesn't exist
        user_ring = truenas_keyring.add_keyring(
            description=username,
            target_keyring=pam_keyring.key.serial
        )

    return user_ring


def get_api_keys_keyring(username: str):
    user_keyring = get_user_keyring(username)

    try:
        api_keys_ring = user_keyring.search(
            key_type=truenas_keyring.KeyType.KEYRING, description=PAM_API_KEY_NAME
        )
    except FileNotFoundError:
        # API_KEYS keyring doesn't exist, create it
        api_keys_ring = truenas_keyring.add_keyring(
            description=PAM_API_KEY_NAME,
            target_keyring=user_keyring.key.serial
        )

    return api_keys_ring


def commit_user_entry(
    username: str,
    api_keys: list[UserApiKey],
    encrypt_fn: callable
) -> None:
    """ Creates or replaces existing API keys in the user's API_KEYS keyring with new ones.
    The API keys are encrypted with the specified encrypt_fn prior to insertion. """
    api_keys_ring = get_api_keys_keyring(username)
    # Clear out existing API_KEYS keyring. We'll replace with new entries
    api_keys_ring.clear()

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
            data=encrypt_fn(dumps(asdict(entry))).encode(),
            target_keyring=api_keys_ring.key.serial
        )

        # Apply timeout if expiry is set (> 0)
        if entry.expiry > 0:
            timeout_seconds = int((expiry_time - now).total_seconds())
            key.set_timeout(timeout=timeout_seconds)


def clear_all_api_keys() -> None:
    """ Clear out all user api keys in the PAM_TRUENAS keyring """
    pam_keyring = get_pam_keyring()

    # Iterate through all user keyrings (unlink expired/revoked while iterating)
    for item in pam_keyring.iter_keyring_contents(unlink_expired=True, unlink_revoked=True):
        # Check if this is a keyring (user keyring)
        if item.key.key_type == "keyring":
            # For each user keyring, try to get and clear their API_KEYS sub-keyring
            try:
                api_keys_ring = item.search(
                    key_type=truenas_keyring.KeyType.KEYRING, description=PAM_API_KEY_NAME
                )
                api_keys_ring.clear()
            except FileNotFoundError:
                # No API_KEYS keyring for this user, skip
                pass


def clear_user_keyring(username: str) -> None:
    """ Clear all API keys in user's API_KEYS keyring """
    api_keys_ring = get_api_keys_keyring(username)
    # Clear out existing API_KEYS keyring
    api_keys_ring.clear()


def dump_user_keyring(username: str, decrypt_fn: callable) -> list:
    """ dump user API key keyring contents. The API keys are
    decrypted with the specified decrypt_fn after read. """
    api_keys_ring = get_api_keys_keyring(username)
    out = []

    for entry in api_keys_ring.list_keyring_contents(unlink_expired=True, unlink_revoked=True):
        data = entry.read_data()
        out.append(loads(decrypt_fn(data.decode())))

    return out
