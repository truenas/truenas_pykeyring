import truenas_api_key.keyring as api_keyring
from truenas_api_key.constants import UserApiKey, ApiKeyAlgorithm, KEYRING_NAME
from middlewared.plugins.pwenc import encrypt, decrypt
import time


# Mock API key data using the UserApiKey dataclass
MOCK_USER_API_KEYS = [
    UserApiKey(
        username="admin",
        dbid=1001,
        algorithm=ApiKeyAlgorithm.SHA512,
        iterations=4096,
        expiry=int(time.time()) + 3600,  # 1 hour from now
        salt="YWRtaW5fc2FsdF8xMjM0",
        server_key="c2VydmVyX2tleV9hZG1pbl8xMjM0",
        stored_key="c3RvcmVkX2tleV9hZG1pbl8xMjM0"
    ),
    UserApiKey(
        username="admin",
        dbid=1002,
        algorithm=ApiKeyAlgorithm.SHA512,
        iterations=2048,
        expiry=int(time.time()) + 7200,  # 2 hours from now
        salt="YWRtaW5fc2FsdF81Njc4",
        server_key="c2VydmVyX2tleV9hZG1pbl81Njc4",
        stored_key="c3RvcmVkX2tleV9hZG1pbl81Njc4"
    ),
    UserApiKey(
        username="testuser",
        dbid=2001,
        algorithm=ApiKeyAlgorithm.SHA512,
        iterations=8192,
        expiry=int(time.time()) + 86400,  # 24 hours from now
        salt="dGVzdHVzZXJfc2FsdF85OTk=",
        server_key="c2VydmVyX2tleV90ZXN0dXNlcl85OTk=",
        stored_key="c3RvcmVkX2tleV90ZXN0dXNlcl85OTk="
    )
]


def test_get_api_keyring():
    """Test getting or creating the main API keyring."""
    keyring = api_keyring.get_api_keyring()

    assert keyring is not None
    assert keyring.key.description == KEYRING_NAME
    assert keyring.key.key_type == "keyring"


def test_get_user_keyring():
    """Test getting or creating user-specific keyrings."""
    admin_keyring = api_keyring.get_user_keyring("admin")
    testuser_keyring = api_keyring.get_user_keyring("testuser")

    assert admin_keyring is not None
    assert admin_keyring.key.description == "admin"
    assert admin_keyring.key.key_type == "keyring"

    assert testuser_keyring is not None
    assert testuser_keyring.key.description == "testuser"
    assert testuser_keyring.key.key_type == "keyring"

    # They should be different keyrings
    assert admin_keyring.key.serial != testuser_keyring.key.serial


def test_commit_user_entry():
    """Test committing API keys for a user."""
    username = "admin"
    admin_keys = [key for key in MOCK_USER_API_KEYS if key.username == username]

    # Commit the admin API keys
    api_keyring.commit_user_entry(username, admin_keys, encrypt)

    # Verify they were stored
    user_keyring = api_keyring.get_user_keyring(username)
    stored_keys = user_keyring.list_keyring_contents()

    # Should have 2 admin keys
    assert len(stored_keys) == 2

    # Verify each key
    stored_dbids = []
    for key in stored_keys:
        assert key.key_type == "user"
        dbid = int(key.description)
        stored_dbids.append(dbid)

        # Read and verify data structure
        key_data = key.read_data()
        import json
        api_key_dict = json.loads(decrypt(key_data.decode()))

        assert api_key_dict["username"] == username
        assert api_key_dict["dbid"] == dbid
        assert api_key_dict["algorithm"] == "SHA512"
        assert "iterations" in api_key_dict
        assert "expiry" in api_key_dict
        assert "salt" in api_key_dict
        assert "server_key" in api_key_dict
        assert "stored_key" in api_key_dict

    # Verify we got the expected dbids
    expected_dbids = [key.dbid for key in admin_keys]
    assert sorted(stored_dbids) == sorted(expected_dbids)


def test_dump_user_keyring():
    """Test dumping user keyring contents."""
    username = "testuser"
    testuser_keys = [key for key in MOCK_USER_API_KEYS if key.username == username]

    # Commit the testuser API key
    api_keyring.commit_user_entry(username, testuser_keys, encrypt)

    # Dump the keyring
    dumped_keys = api_keyring.dump_user_keyring(username, decrypt)

    # Should have 1 testuser key
    assert len(dumped_keys) == 1

    # Verify the dumped data matches original
    dumped_key = dumped_keys[0]
    original_key = testuser_keys[0]

    assert dumped_key["username"] == original_key.username
    assert dumped_key["dbid"] == original_key.dbid
    assert dumped_key["algorithm"] == original_key.algorithm
    assert dumped_key["iterations"] == original_key.iterations
    assert dumped_key["expiry"] == original_key.expiry
    assert dumped_key["salt"] == original_key.salt
    assert dumped_key["server_key"] == original_key.server_key
    assert dumped_key["stored_key"] == original_key.stored_key


def test_clear_user_keyring():
    """Test clearing a user's keyring."""
    username = "admin"
    admin_keys = [key for key in MOCK_USER_API_KEYS if key.username == username]

    # First, commit some keys
    api_keyring.commit_user_entry(username, admin_keys, encrypt)

    # Verify they exist
    dumped_keys = api_keyring.dump_user_keyring(username, decrypt)
    assert len(dumped_keys) == len(admin_keys)

    # Clear the keyring
    api_keyring.clear_user_keyring(username)

    # Verify it's empty
    dumped_keys = api_keyring.dump_user_keyring(username, decrypt)
    assert len(dumped_keys) == 0


def test_clear_all_api_keys():
    """Test clearing all API keys."""
    # First, commit keys for multiple users
    for username in ["admin", "testuser"]:
        user_keys = [key for key in MOCK_USER_API_KEYS if key.username == username]
        api_keyring.commit_user_entry(username, user_keys, encrypt)

    # Verify they exist
    admin_keys = api_keyring.dump_user_keyring("admin", decrypt)
    testuser_keys = api_keyring.dump_user_keyring("testuser", decrypt)
    assert len(admin_keys) > 0
    assert len(testuser_keys) > 0

    # Clear all API keys
    api_keyring.clear_all_api_keys()

    # Verify all user keyrings are gone/empty
    # Note: This clears the entire API keyring, so user keyrings won't exist
    # anymore
    api_key_keyring = api_keyring.get_api_keyring()
    contents = api_key_keyring.list_keyring_contents()
    assert len(contents) == 0


def test_commit_entry_overwrites_existing():
    """Test that committing new entries overwrites existing ones."""
    username = "admin"
    admin_keys = [key for key in MOCK_USER_API_KEYS if key.username == username]

    # Commit initial keys
    api_keyring.commit_user_entry(username, admin_keys, encrypt)
    initial_dump = api_keyring.dump_user_keyring(username, decrypt)
    assert len(initial_dump) == 2

    # Commit with only one key (should replace all)
    single_key = [admin_keys[0]]
    api_keyring.commit_user_entry(username, single_key, encrypt)

    # Should now only have one key
    new_dump = api_keyring.dump_user_keyring(username, decrypt)
    assert len(new_dump) == 1
    assert new_dump[0]["dbid"] == single_key[0].dbid


def test_dataclass_serialization():
    """Test that UserApiKey dataclass serializes/deserializes correctly."""
    original_key = MOCK_USER_API_KEYS[0]

    # Commit and retrieve
    api_keyring.commit_user_entry(original_key.username, [original_key], encrypt)
    dumped_keys = api_keyring.dump_user_keyring(original_key.username, decrypt)

    recovered_key_dict = dumped_keys[0]

    # Reconstruct the dataclass
    recovered_key = UserApiKey(**recovered_key_dict)

    # Should be identical
    assert recovered_key == original_key


def test_algorithm_enum():
    """Test ApiKeyAlgorithm enum functionality."""
    assert ApiKeyAlgorithm.SHA512 == "SHA512"

    # Test enum in dataclass with SHA512
    key_sha512 = UserApiKey(
        username="test",
        dbid=999,
        algorithm=ApiKeyAlgorithm.SHA512,
        iterations=4096,
        expiry=1234567890,
        salt="test_salt",
        server_key="test_server_key",
        stored_key="test_stored_key"
    )

    assert key_sha512.algorithm == "SHA512"
