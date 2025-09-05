# TrueNAS Keyring Module

Python C extension for Linux keyutils integration with high-level API key management.

## Source Files

### C Extension (`src/`)

- **`truenas_keyring.h`** - Main header with struct definitions and function declarations
- **`truenas_keyring.c`** - Module initialization and module-level methods
- **`py_tn_key.c`** - TNKey type implementation for individual keys
- **`py_tn_keyring.c`** - TNKeyring type implementation for keyring containers
- **`py_tn_key_enum.c`** - KeyType and SpecialKeyring enum implementations
- **`py_key_utils.c`** - Utility functions for key operations and object creation

### Python Package (`src/truenas_api_key/`)

- **`__init__.py`** - Package initialization and public API exports
- **`constants.py`** - UserApiKey dataclass and ApiKeyAlgorithm enum
- **`keyring.py`** - High-level API key management functions

### Tests (`tests/`)

- **`test_basic.py`** - C extension functionality tests
- **`test_truenas_api_key.py`** - Python package functionality tests