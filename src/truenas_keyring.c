#include "truenas_keyring.h"

PyDoc_STRVAR(tn_request_key__doc__,
"request_key(*, key_type, description) -> truenas_keyring.TNKey | truenas_keyring.TNKeyring\n"
"-----------------------------------------------------------------------------------------\n\n"
"Request a key from the kernel keyring system.\n"
"See man (2) request_key for more information.\n\n"
""
"Parameters\n"
"----------\n"
"key_type: truenas_keyring.KeyType, required\n"
"    The type of key to request (e.g., \"user\", \"keyring\").\n"
"    Must be a truenas_keyring.KeyType enum value.\n\n"
"description: str, required\n"
"    A string that describes the key to search for.\n"
"    This is used to identify the key in the keyring.\n\n"
""
"Returns\n"
"-------\n"
"truenas_keyring.TNKey | truenas_keyring.TNKeyring\n"
"    TNKey object if the key type is not \"keyring\"\n"
"    TNKeyring object if the key type is \"keyring\"\n\n"
""
"Raises\n"
"------\n"
"TypeError:\n"
"    Invalid key_type or description parameter type.\n"
"ValueError:\n"
"    Missing required parameter.\n"
"truenas_keyring.KeyringError:\n"
"    System call failed (see errno for details).\n\n"
);

static PyObject *
tn_request_key(PyObject *module_obj, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = {"key_type", "description", NULL};
	PyObject *key_type_obj = NULL;
	const char *key_type_str;
	const char *description_str;
	key_serial_t serial;
	PyObject *tnkey_instance;
	tn_module_state_t *state;

	state = (tn_module_state_t *)PyModule_GetState(module_obj);
	if (state == NULL) {
		return NULL;
	}

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "$Os:request_key",
					 kwlist, &key_type_obj,
					 &description_str)) {
		return NULL;
	}

	if (key_type_obj == NULL || key_type_obj == Py_None) {
		PyErr_SetString(PyExc_ValueError,
				"key_type argument is required");
		return NULL;
	}


	if (!PyObject_IsInstance(key_type_obj, state->keytype_enum)) {
		PyObject *repr = PyObject_Repr(key_type_obj);
		PyErr_Format(PyExc_TypeError,
			     "%V: unexpected key_type. "
			     "Expected a " MODULE_NAME ".KeyType instance.",
			     repr, "UNKNOWN");
		Py_XDECREF(repr);
		return NULL;
	}


	key_type_str = PyUnicode_AsUTF8(key_type_obj);
	if (key_type_str == NULL) {
		return NULL;
	}


	Py_BEGIN_ALLOW_THREADS
	serial = request_key(key_type_str, description_str, NULL, 0);
	Py_END_ALLOW_THREADS

	if (serial == -1) {
		PyErr_SetFromErrno(get_keyring_error_from_module(module_obj));
		return NULL;
	}

	tnkey_instance = create_key_object_from_serial(serial, module_obj);

	return tnkey_instance;
}

PyDoc_STRVAR(tn_revoke_key__doc__,
"revoke_key(*, serial) -> None\n"
"----------------------------\n\n"
"Revoke a key by marking it as revoked, preventing further use.\n"
"See man (3) keyctl_revoke for more information.\n\n"
""
"Parameters\n"
"----------\n"
"serial: int, required\n"
"    The serial number of the key to revoke.\n\n"
""
"Returns\n"
"-------\n"
"None\n\n"
""
"Raises\n"
"------\n"
"truenas_keyring.KeyringError:\n"
"    System call failed (see errno for details).\n\n"
);

static PyObject *
tn_revoke_key(PyObject *module_obj, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = {"serial", NULL};
	key_serial_t serial;
	long result;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "$i:revoke_key",
					 kwlist, &serial)) {
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	result = keyctl_revoke(serial);
	Py_END_ALLOW_THREADS

	if (result == -1) {
		PyErr_SetFromErrno(get_keyring_error_from_module(module_obj));
		return NULL;
	}

	Py_RETURN_NONE;
}

PyDoc_STRVAR(tn_invalidate_key__doc__,
"invalidate_key(*, serial) -> None\n"
"--------------------------------\n\n"
"Invalidate a key, marking it as invalid and immediately removing\n"
"it from the keyring. This is more immediate than revocation.\n"
"See man (3) keyctl_invalidate for more information.\n\n"
""
"Parameters\n"
"----------\n"
"serial: int, required\n"
"    The serial number of the key to invalidate.\n\n"
""
"Returns\n"
"-------\n"
"None\n\n"
""
"Raises\n"
"------\n"
"truenas_keyring.KeyringError:\n"
"    System call failed (see errno for details).\n\n"
);

static PyObject *
tn_invalidate_key(PyObject *module_obj, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = {"serial", NULL};
	key_serial_t serial;
	long result;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "$i:invalidate_key",
					 kwlist, &serial)) {
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	result = keyctl_invalidate(serial);
	Py_END_ALLOW_THREADS

	if (result == -1) {
		PyErr_SetFromErrno(get_keyring_error_from_module(module_obj));
		return NULL;
	}

	Py_RETURN_NONE;
}

PyDoc_STRVAR(tn_get_persistent_keyring__doc__,
"get_persistent_keyring(*, uid=-1) -> truenas_keyring.TNKeyring\n"
"-------------------------------------------------------------\n\n"
"Get the persistent keyring for the specified user.\n"
"The persistent keyring is a keyring that is linked to the user\n"
"and persists for as long as the user has sessions on the system.\n"
"It is automatically cleaned up when the user has no more sessions.\n"
"See man (3) keyctl_get_persistent for more information.\n\n"
""
"Parameters\n"
"----------\n"
"uid: int, optional, default=-1\n"
"    The user ID (UID) of the user whose persistent keyring\n"
"    is being retrieved. If -1, uses the current process's\n"
"    real user ID.\n\n"
""
"Returns\n"
"-------\n"
"truenas_keyring.TNKeyring\n"
"    The persistent keyring for the specified user.\n\n"
""
"Raises\n"
"------\n"
"truenas_keyring.KeyringError:\n"
"    System call failed (see errno for details).\n\n"
);

static PyObject *
tn_get_persistent_keyring(PyObject *module_obj, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = {"uid", NULL};
	int uid = -1;
	key_serial_t serial;
	PyObject *keyring_instance;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|$i",
					 kwlist, &uid)) {
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	serial = keyctl_get_persistent((uid_t)uid, KEY_SPEC_PROCESS_KEYRING);
	Py_END_ALLOW_THREADS

	if (serial == -1) {
		PyErr_SetFromErrno(get_keyring_error_from_module(module_obj));
		return NULL;
	}

	keyring_instance = create_key_object_from_serial(serial, module_obj);

	return keyring_instance;
}

PyDoc_STRVAR(tn_add_key__doc__,
"add_key(*, key_type, description, data, target_keyring) -> truenas_keyring.TNKey\n"
"------------------------------------------------------------------------------\n\n"
"Add a new key to the specified keyring.\n"
"See man (2) add_key for more information.\n\n"
""
"Parameters\n"
"----------\n"
"key_type: str, required\n"
"    The type of key to create (e.g., \"user\", \"logon\"). Cannot be \"keyring\".\n\n"
"description: str, required\n"
"    A string that describes the key.\n\n"
"data: bytes, required\n"
"    The key data payload as bytes.\n\n"
"target_keyring: int, required\n"
"    The serial number of the keyring to add the key to.\n\n"
""
"Returns\n"
"-------\n"
"truenas_keyring.TNKey\n"
"    The newly created key object.\n\n"
""
"Raises\n"
"------\n"
"TypeError:\n"
"    Invalid parameter type.\n"
"ValueError:\n"
"    You supplied a \"keyring\" key type, use add_keyring instead (and maybe read docs\n"
"    a little more carefully).\n"
"truenas_keyring.KeyringError:\n"
"    System call failed (see errno for details).\n\n"
);

static PyObject *
tn_add_key(PyObject *module_obj, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = {"key_type", "description", "data", "target_keyring", NULL};
	const char *key_type_str;
	const char *description_str;
	const char *data_buf;
	Py_ssize_t data_len;
	int target_keyring;
	key_serial_t serial;
	PyObject *key_instance;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "$ssy#i:add_key",
					 kwlist, &key_type_str, &description_str,
					 &data_buf, &data_len, &target_keyring)) {
		return NULL;
	}

	/* Prevent creating keyring type with add_key */
	if (strcmp(key_type_str, KEY_TYPE_STR_KEYRING) == 0) {
		PyErr_SetString(PyExc_ValueError, "Cannot create keyring with add_key, use add_keyring instead");
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	serial = add_key(key_type_str, description_str, data_buf, data_len, target_keyring);
	Py_END_ALLOW_THREADS

	if (serial == -1) {
		PyErr_SetFromErrno(get_keyring_error_from_module(module_obj));
		return NULL;
	}

	key_instance = create_key_object_from_serial(serial, module_obj);

	return key_instance;
}

PyDoc_STRVAR(tn_add_keyring__doc__,
"add_keyring(*, description, target_keyring) -> truenas_keyring.TNKeyring\n"
"-----------------------------------------------------------------------\n\n"
"Add a new keyring to the specified keyring.\n"
"See man (2) add_key for more information.\n\n"
""
"Parameters\n"
"----------\n"
"description: str, required\n"
"    A string that describes the keyring.\n\n"
"target_keyring: int, required\n"
"    The serial number of the keyring to add the new keyring to.\n\n"
""
"Returns\n"
"-------\n"
"truenas_keyring.TNKeyring\n"
"    The newly created keyring object.\n\n"
""
"Raises\n"
"------\n"
"TypeError:\n"
"    Invalid parameter type.\n"
"truenas_keyring.KeyringError:\n"
"    System call failed (see errno for details).\n\n"
);

static PyObject *
tn_add_keyring(PyObject *module_obj, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = {"description", "target_keyring", NULL};
	const char *description_str;
	int target_keyring;
	key_serial_t serial;
	PyObject *keyring_instance;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "$si:add_keyring",
					 kwlist, &description_str, &target_keyring)) {
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	serial = add_key(KEY_TYPE_STR_KEYRING, description_str, NULL, 0, target_keyring);
	Py_END_ALLOW_THREADS

	if (serial == -1) {
		PyErr_SetFromErrno(get_keyring_error_from_module(module_obj));
		return NULL;
	}

	keyring_instance = create_key_object_from_serial(serial, module_obj);

	return keyring_instance;
}

static PyMethodDef tn_module_methods[] = {
	{
		.ml_name = "request_key",
		.ml_meth = (PyCFunction)tn_request_key,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = tn_request_key__doc__
	},
	{
		.ml_name = "revoke_key",
		.ml_meth = (PyCFunction)tn_revoke_key,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = tn_revoke_key__doc__
	},
	{
		.ml_name = "invalidate_key",
		.ml_meth = (PyCFunction)tn_invalidate_key,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = tn_invalidate_key__doc__
	},
	{
		.ml_name = "get_persistent_keyring",
		.ml_meth = (PyCFunction)tn_get_persistent_keyring,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = tn_get_persistent_keyring__doc__
	},
	{
		.ml_name = "add_key",
		.ml_meth = (PyCFunction)tn_add_key,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = tn_add_key__doc__
	},
	{
		.ml_name = "add_keyring",
		.ml_meth = (PyCFunction)tn_add_keyring,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = tn_add_keyring__doc__
	},
	{NULL, NULL, 0, NULL}
};

static int
tn_module_clear(PyObject *m)
{
	tn_module_state_t *state = (tn_module_state_t *)PyModule_GetState(m);
	if (state) {
		Py_CLEAR(state->special_keyring_enum);
		Py_CLEAR(state->keytype_enum);
		Py_CLEAR(state->keyring_error);
	}
	return 0;
}

static void
tn_module_free(void *m)
{
	tn_module_clear((PyObject *)m);
}

static PyModuleDef truenas_keyring_module = {
	PyModuleDef_HEAD_INIT,
	.m_name = MODULE_NAME,
	.m_doc = "TrueNAS keyring module",
	.m_size = sizeof(tn_module_state_t),
	.m_methods = tn_module_methods,
	.m_clear = tn_module_clear,
	.m_free = tn_module_free,
};

PyMODINIT_FUNC
PyInit_truenas_keyring(void)
{
	PyObject *m;

	if (PyType_Ready(&TNKeyType) < 0) {
		return NULL;
	}

	if (PyType_Ready(&TNKeyringType) < 0) {
		return NULL;
	}

	if (PyType_Ready(&TNKeyringIterType) < 0) {
		return NULL;
	}

	m = PyModule_Create(&truenas_keyring_module);
	if (m == NULL) {
		return NULL;
	}


	if (tn_key_add_enums_to_module(m) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	/* Create KeyringError exception */
	tn_module_state_t *state = (tn_module_state_t *)PyModule_GetState(m);
	if (state == NULL) {
		Py_DECREF(m);
		return NULL;
	}

	state->keyring_error = PyErr_NewException(MODULE_NAME ".KeyringError", PyExc_OSError, NULL);
	if (state->keyring_error == NULL) {
		Py_DECREF(m);
		return NULL;
	}

	Py_INCREF(state->keyring_error);
	if (PyModule_AddObject(m, "KeyringError", state->keyring_error) < 0) {
		Py_DECREF(state->keyring_error);
		Py_DECREF(m);
		return NULL;
	}

	return m;
}
