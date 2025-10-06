# TrueNAS Python Keyring

A CPython extension for the Linux keyring system designed for TrueNAS middleware API key management. This repository provides a subset of libkeyutils functionality and will be expanded only as needed for internal TrueNAS purposes.

## Components

truenas_keyring - C extension module that interfaces with the Linux kernel keyring via libkeyutils
truenas_api_key - Python package for API key management built on the C extension

## C Extension (src/)

truenas_keyring.h - Main header with struct definitions and function declarations
truenas_keyring.c - Module initialization and module-level methods
py_tn_key.c - TNKey type implementation for individual keys
py_tn_keyring.c - TNKeyring type implementation for keyring containers
py_tn_keyring_iter.c - Iterator implementation for keyring contents
py_tn_key_enum.c - KeyType and SpecialKeyring enum implementations
py_key_utils.c - Utility functions for key operations and object creation

## Python Package (src/truenas_api_key/)

__init__.py - Package initialization and public API exports
constants.py - UserApiKey dataclass and ApiKeyAlgorithm enum
keyring.py - High-level API key management functions

## Keyring Structure

The API keys are organized in a hierarchical keyring structure:

```
persistent-keyring:uid=0
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
    │   │   └── ...
    │   ├── SESSIONS/
    │   └── FAILLOG/
    └── ...
```

## High-Level API Functions

The `truenas_api_key.keyring` module provides the following functions:

- `get_pam_keyring()` - Get or create the main PAM_TRUENAS keyring
- `get_user_keyring(username)` - Get or create a user's keyring
- `get_api_keys_keyring(username)` - Get or create a user's API_KEYS sub-keyring
- `commit_user_entry(username, api_keys, encrypt_fn)` - Store API keys for a user
- `dump_user_keyring(username, decrypt_fn)` - Retrieve and decrypt API keys for a user
- `clear_user_keyring(username)` - Clear all API keys for a specific user
- `clear_all_api_keys()` - Clear API keys for all users (preserves user keyrings)

## Tests (tests/)

test_basic.py - C extension functionality tests
test_truenas_api_key.py - Python package functionality tests