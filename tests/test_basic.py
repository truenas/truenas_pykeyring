import pytest
import truenas_keyring


def test_module_import():
	"""Test that the module can be imported successfully."""
	assert hasattr(truenas_keyring, 'KeyType')
	assert hasattr(truenas_keyring, 'SpecialKeyring')
	assert hasattr(truenas_keyring, 'KeyringError')


def test_enums_exist():
	"""Test that required enums are available."""
	assert hasattr(truenas_keyring.KeyType, 'USER')
	assert hasattr(truenas_keyring.KeyType, 'KEYRING')
	assert hasattr(truenas_keyring.SpecialKeyring, 'SESSION')
	assert hasattr(truenas_keyring.SpecialKeyring, 'USER')


def test_module_methods_exist():
	"""Test that all expected module methods are available."""
	assert hasattr(truenas_keyring, 'request_key')
	assert hasattr(truenas_keyring, 'revoke_key')
	assert hasattr(truenas_keyring, 'invalidate_key')
	assert hasattr(truenas_keyring, 'get_persistent_keyring')
	assert hasattr(truenas_keyring, 'add_key')
	assert hasattr(truenas_keyring, 'add_keyring')


def test_get_persistent_keyring():
	"""Test getting the persistent keyring for current user."""
	keyring = truenas_keyring.get_persistent_keyring()
	assert keyring is not None
	assert hasattr(keyring, 'key')
	assert hasattr(keyring, 'clear')
	assert hasattr(keyring, 'list_keyring_contents')

	# Test that key returns a TNKey object
	key_obj = keyring.key
	assert key_obj is not None
	assert hasattr(key_obj, 'serial')
	assert hasattr(key_obj, 'key_type')
	assert hasattr(key_obj, 'description')


def test_add_keyring():
	"""Test creating a new keyring."""
	# Get persistent keyring to use as parent
	parent_keyring = truenas_keyring.get_persistent_keyring()
	parent_serial = parent_keyring.key.serial

	# Create new keyring
	new_keyring = truenas_keyring.add_keyring(
		description="test_keyring",
		target_keyring=parent_serial
	)

	assert new_keyring is not None
	assert hasattr(new_keyring, 'key')

	# Verify it's actually a keyring
	key_obj = new_keyring.key
	assert key_obj.key_type == "keyring"
	assert key_obj.description == "test_keyring"

	# Clean up - revoke the test keyring
	truenas_keyring.revoke_key(serial=key_obj.serial)


def test_add_key():
	"""Test creating a new key."""
	# Get persistent keyring to use as parent
	parent_keyring = truenas_keyring.get_persistent_keyring()
	parent_serial = parent_keyring.key.serial

	# Create new key
	test_data = b"test_key_data"
	new_key = truenas_keyring.add_key(
		key_type="user",
		description="test_key",
		data=test_data,
		target_keyring=parent_serial
	)

	assert new_key is not None
	assert hasattr(new_key, 'serial')
	assert hasattr(new_key, 'key_type')
	assert hasattr(new_key, 'description')
	assert hasattr(new_key, 'read_data')

	# Verify key properties
	assert new_key.key_type == "user"
	assert new_key.description == "test_key"

	# Verify key data
	read_data = new_key.read_data()
	assert read_data == test_data

	# Clean up - revoke the test key
	truenas_keyring.revoke_key(serial=new_key.serial)


def test_add_key_rejects_keyring_type():
	"""Test that add_key rejects keyring type."""
	parent_keyring = truenas_keyring.get_persistent_keyring()
	parent_serial = parent_keyring.key.serial

	with pytest.raises(ValueError, match="Cannot create keyring with add_key, use add_keyring instead"):
		truenas_keyring.add_key(
			key_type="keyring",
			description="test",
			data=b"data",
			target_keyring=parent_serial
		)


def test_request_key_nonexistent():
	"""Test requesting a key that doesn't exist."""
	with pytest.raises(truenas_keyring.KeyringError):
		truenas_keyring.request_key(
			key_type=truenas_keyring.KeyType.USER,
			description="nonexistent_key_12345"
		)


def test_revoke_invalid_serial():
	"""Test revoking a key with invalid serial."""
	with pytest.raises(truenas_keyring.KeyringError):
		truenas_keyring.revoke_key(serial=999999999)


def test_invalidate_invalid_serial():
	"""Test invalidating a key with invalid serial."""
	with pytest.raises(truenas_keyring.KeyringError):
		truenas_keyring.invalidate_key(serial=999999999)