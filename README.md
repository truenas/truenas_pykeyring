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
py_tn_key_enum.c - KeyType and SpecialKeyring enum implementations
py_key_utils.c - Utility functions for key operations and object creation

## Python Package (src/truenas_api_key/)

__init__.py - Package initialization and public API exports
constants.py - UserApiKey dataclass and ApiKeyAlgorithm enum
keyring.py - High-level API key management functions

## Tests (tests/)

test_basic.py - C extension functionality tests
test_truenas_api_key.py - Python package functionality tests