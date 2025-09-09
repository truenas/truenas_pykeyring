from setuptools import setup, Extension, find_packages

truenas_keyring_ext = Extension(
    'truenas_keyring',
    sources=[
        'src/truenas_keyring.c',
        'src/py_key_utils.c',
        'src/py_tn_key.c',
        'src/py_tn_keyring.c',
        'src/py_tn_key_enum.c'
    ],
    include_dirs=['src'],
    libraries=['keyutils']
)

setup(
    packages=['truenas_api_key'],
    package_dir={'truenas_api_key': 'src/truenas_api_key'},
    ext_modules=[truenas_keyring_ext]
)
