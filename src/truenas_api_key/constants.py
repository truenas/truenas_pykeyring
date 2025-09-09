from dataclasses import dataclass
from enum import StrEnum


KEYRING_NAME = 'TRUENAS_API_KEYS'


class ApiKeyAlgorithm(StrEnum):
    """ Crypto algorithms supported for auth. Currently only SHA512,
    but maybe more in the future. """
    SHA512 = 'SHA512'


@dataclass
class UserApiKey:
    """ Data class for new API keys. This will be converted into kernel keyring entries. """
    username: str  # name of the user
    dbid: int  # datastore primary key where API key is stored.
    # Also used as identifier in user keyring.
    algorithm: ApiKeyAlgorithm
    iterations: int  # number of iterations of pbkdf2_hmac for algorithm
    expiry: int  # unix timestamp for api key
    salt: str  # base64 cryptographic salt
    server_key: str  # base64 SCRAM ServerKey
    stored_key: str  # base64 SCRAM StoredKey
