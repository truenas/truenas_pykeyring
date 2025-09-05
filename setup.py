from setuptools import setup, Extension

truenas_keyring_module = Extension(
    'truenas_keyring',
    sources=[
        'src/truenas_keyring.c',
        'src/py_key_utils.c',
        'src/py_tn_key.c',
        'src/py_tn_keyring.c',
        'src/py_tn_key_enum.c'
    ],
    include_dirs=[
        'src'
    ],
    libraries=['keyutils'],
)

setup(
    name='truenas_keyring',
    version='0.1.0',
    description='TrueNAS keyring module',
    ext_modules=[truenas_keyring_module],
    packages=['truenas_api_key'],
    package_dir={'truenas_api_key': 'src/truenas_api_key'},
)
