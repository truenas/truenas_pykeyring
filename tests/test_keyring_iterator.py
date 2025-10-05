import pytest
import truenas_keyring


def test_iter_keyring_contents_method_exists():
    """Test that iter_keyring_contents method exists on TNKeyring."""
    keyring = truenas_keyring.get_persistent_keyring()
    assert hasattr(keyring, 'iter_keyring_contents')
    assert callable(keyring.iter_keyring_contents)


def test_iter_keyring_contents_returns_iterator():
    """Test that iter_keyring_contents returns an iterator."""
    keyring = truenas_keyring.get_persistent_keyring()
    iterator = keyring.iter_keyring_contents()

    # Check it's an iterator
    assert hasattr(iterator, '__iter__')
    assert hasattr(iterator, '__next__')

    # Iterator should return itself from __iter__
    assert iterator.__iter__() is iterator


def test_iter_keyring_contents_basic():
    """Test basic iteration over keyring contents."""
    keyring = truenas_keyring.get_persistent_keyring()

    # Create a test keyring and add some keys to ensure we have content
    test_keyring = truenas_keyring.add_keyring(
        description="test_iterator_keyring",
        target_keyring=keyring.key.serial
    )

    # Add some test keys
    test_keys = []
    for i in range(3):
        key = truenas_keyring.add_key(
            key_type=truenas_keyring.KeyType.USER,
            description=f"test_iter_key_{i}",
            data=f"test_data_{i}".encode(),
            target_keyring=test_keyring.key.serial
        )
        test_keys.append(key)

    # Iterate through the keyring
    found_keys = []
    for key in test_keyring.iter_keyring_contents():
        found_keys.append(key)

    # Should find all the keys we added
    assert len(found_keys) == 3

    # Each item should be a TNKey
    for key in found_keys:
        assert hasattr(key, 'serial')
        assert hasattr(key, 'description')

    # Clean up
    test_keyring.clear()
    truenas_keyring.invalidate_key(serial=test_keyring.key.serial)


def test_iter_keyring_contents_empty_keyring():
    """Test iteration over an empty keyring."""
    # Create an empty keyring
    keyring = truenas_keyring.get_persistent_keyring()
    test_keyring = truenas_keyring.add_keyring(
        description="test_empty_iterator",
        target_keyring=keyring.key.serial
    )

    # Iteration should work but return no items
    items = list(test_keyring.iter_keyring_contents())
    assert items == []

    # Clean up
    truenas_keyring.invalidate_key(serial=test_keyring.key.serial)


def test_iter_keyring_contents_with_parameters():
    """Test iter_keyring_contents with unlink_expired and unlink_revoked parameters."""
    keyring = truenas_keyring.get_persistent_keyring()

    # Test that parameters are accepted (actual behavior depends on having expired/revoked keys)
    iterator1 = keyring.iter_keyring_contents(unlink_expired=True)
    assert iterator1 is not None

    iterator2 = keyring.iter_keyring_contents(unlink_revoked=True)
    assert iterator2 is not None

    iterator3 = keyring.iter_keyring_contents(unlink_expired=True, unlink_revoked=True)
    assert iterator3 is not None

    # Consume iterators to ensure they work
    _ = list(iterator1)
    _ = list(iterator2)
    _ = list(iterator3)


def test_iter_vs_list_consistency():
    """Test that iter_keyring_contents returns same keys as list_keyring_contents."""
    keyring = truenas_keyring.get_persistent_keyring()

    # Create a test keyring
    test_keyring = truenas_keyring.add_keyring(
        description="test_iter_vs_list",
        target_keyring=keyring.key.serial
    )

    # Add some test keys
    for i in range(5):
        truenas_keyring.add_key(
            key_type=truenas_keyring.KeyType.USER,
            description=f"consistency_test_{i}",
            data=f"data_{i}".encode(),
            target_keyring=test_keyring.key.serial
        )

    # Get keys via list method
    list_keys = test_keyring.list_keyring_contents()
    list_serials = {key.serial for key in list_keys}

    # Get keys via iterator
    iter_keys = list(test_keyring.iter_keyring_contents())
    iter_serials = {key.serial for key in iter_keys}

    # Both methods should return the same keys
    assert list_serials == iter_serials
    assert len(list_keys) == len(iter_keys)

    # Clean up
    test_keyring.clear()
    truenas_keyring.invalidate_key(serial=test_keyring.key.serial)


def test_iterator_multiple_iterations():
    """Test that we can create multiple iterators from the same keyring."""
    keyring = truenas_keyring.get_persistent_keyring()

    # Create a test keyring with some content
    test_keyring = truenas_keyring.add_keyring(
        description="test_multiple_iters",
        target_keyring=keyring.key.serial
    )

    for i in range(3):
        truenas_keyring.add_key(
            key_type=truenas_keyring.KeyType.USER,
            description=f"multi_iter_key_{i}",
            data=f"data_{i}".encode(),
            target_keyring=test_keyring.key.serial
        )

    # Create multiple iterators
    iter1 = test_keyring.iter_keyring_contents()
    iter2 = test_keyring.iter_keyring_contents()

    # Both should work independently
    keys1 = list(iter1)
    keys2 = list(iter2)

    assert len(keys1) == 3
    assert len(keys2) == 3

    # They should return the same keys (though not necessarily the same order)
    serials1 = {k.serial for k in keys1}
    serials2 = {k.serial for k in keys2}
    assert serials1 == serials2

    # Clean up
    test_keyring.clear()
    truenas_keyring.invalidate_key(serial=test_keyring.key.serial)