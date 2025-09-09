/* Common utilities for keyring-related operations */

#include "truenas_keyring.h"


/*
 * Retrieve description of key. Allocates memory that must be freed using
 * PyMem_RawFree().
 *
 * Does not require GIL. Caller should generate exception
 * from errno.
 */
char *get_key_description(key_serial_t serial)
{
	long bufsz, res;
	char *desc;

	bufsz = keyctl_describe(serial, NULL, 0);
	if (bufsz == -1) {
		return NULL;
	}

	desc = PyMem_RawMalloc(bufsz);
	if (desc == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	res = keyctl_describe(serial, desc, bufsz);
	if (res == -1) {
		PyMem_RawFree(desc);
		return NULL;
	}

	return desc;
}

/*
 * Simple check to determine whether the key with the specified serial has the
 * expected key type. Does not require GIL. Caller should use errno to set exception.
 */
bool check_key_type(key_serial_t serial, const char *key_type_str, bool *match_out)
{
	bool match;
	char *desc;
	char *type_found;

	desc = get_key_description(serial);
	if (desc == NULL)
		return false;


	type_found = strtok(desc, ";");
	if (type_found == NULL) {
		PyMem_RawFree(desc);
		errno = ENOENT;
		return false;
	}

	match = strcmp(key_type_str, type_found) == 0;
	PyMem_RawFree(desc);

	*match_out = match;
	return true;
}

/*
 * Retrieve an array of serial numbers of keys within the specified keyring.
 * Passes out pointer to keyring array and number of members of array.
 * Does not require GIL.
 *
 * On failure, errno will be set to a relevant value that can be used
 * to generate an appropriate OSError or TNKeyError exception.
 *
 * NOTE: caller must free keys_out via PyMem_RawFree()
 */
bool get_keyring_serials(key_serial_t serial, key_serial_t **keys_out, size_t *cnt_out)
{
	long res;
	size_t bufsz;
	key_serial_t *keys;
	bool is_keyring, success;

	/* First check whether the provided serial is actually a keyring */
	success = check_key_type(serial, KEY_TYPE_STR_KEYRING, &is_keyring);
	if (!success)
		return false;

	if (!is_keyring) {
		errno = EINVAL;
		return false;
	}

	res = keyctl_read(serial, NULL, 0);
	if (res == -1) {
		return false;
	}
	bufsz = (size_t)res;

	keys = (key_serial_t *)PyMem_RawMalloc(bufsz);
	if (keys == NULL) {
		errno = ENOMEM;
		return false;
	}

	res = keyctl_read(serial, (char *)keys, bufsz);
	if (res == -1) {
		PyMem_RawFree(keys);
		return false;
	}

	if (res % sizeof(key_serial_t) != 0) {
		// This shouldn't happen, but perhaps we got a short read
		// or the length of read isn't what's expected for an array of serials
		errno = EINVAL;
		PyMem_RawFree(keys);
		return false;
	}

	*keys_out = (key_serial_t *)keys;
	*cnt_out = bufsz / sizeof(key_serial_t);

	return true;
}

/*
 * Retrieve the data for a given serial that's *not* a keyring.
 * data_out must be freed via PyMem_RawFree(). Does not require GIL.
 */
bool get_key_data(key_serial_t serial, char **data_out, size_t *data_len)
{
	long res;
	size_t bufsz;
	char *data;
	bool is_keyring, success;

	/* First check whether the provided serial is actually a keyring */
	success = check_key_type(serial, KEY_TYPE_STR_KEYRING, &is_keyring);
	if (!success)
		return false;

	/* There's a separate function to get keyring serials */
	if (is_keyring) {
		errno = EINVAL;
		return false;
	}

	res = keyctl_read(serial, NULL, 0);
	if (res == -1) {
		return false;
	}
	bufsz = (size_t)res;

	data = PyMem_RawMalloc(bufsz);
	if (data == NULL) {
		errno = ENOMEM;
		return false;
	}

	res = keyctl_read(serial, data, bufsz);
	if (res == -1) {
		PyMem_RawFree(data);
		return false;
	}

	*data_out = data;
	*data_len = bufsz;

	return true;
}

/*
 * Create appropriate Python key object (TNKey or TNKeyring) from a serial number.
 * Requires GIL to be held when calling this function.
 */
PyObject *
create_key_object_from_serial(key_serial_t key_serial, PyObject *module_obj)
{
	bool is_keyring, success;
	PyObject *py_key_obj;

	Py_BEGIN_ALLOW_THREADS
	success = check_key_type(key_serial, KEY_TYPE_STR_KEYRING, &is_keyring);
	Py_END_ALLOW_THREADS
	if (!success) {
		PyErr_SetFromErrno(get_keyring_error_from_module(module_obj));
		return NULL;
	}

	/*
	 * The following will initialize new TNKey or TNKeyring objects. The paramers are passed
	 * to the tp_init (init) functions of the objects. We need to store a reference to the
	 * module oject so that the object's type methods will be able to access data stored in the
	 * module state.
	 */
	if (is_keyring) {
		py_key_obj = PyObject_CallFunction((PyObject *)&TNKeyringType, "iO", key_serial, module_obj);
	} else {
		py_key_obj = PyObject_CallFunction((PyObject *)&TNKeyType, "iO", key_serial, module_obj);
	}

	return py_key_obj;
}

/*
 * Helper function to get KeyringError from module.
 * Requires GIL to be held when calling this function.
 */
PyObject *
get_keyring_error_from_module(PyObject *module_obj)
{
	tn_module_state_t *state = (tn_module_state_t *)PyModule_GetState(module_obj);
	if (state == NULL) {
		return PyExc_OSError;  /* Fallback to OSError if we can't get the state */
	}
	return state->keyring_error;
}
