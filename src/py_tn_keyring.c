#include "truenas_keyring.h"

static void
py_tn_keyring_dealloc(py_tn_keyring_t *self)
{
	Py_CLEAR(self->py_key);
	Py_TYPE(self)->tp_free((PyObject *) self);
}

static int
py_tn_keyring_init(py_tn_keyring_t *self, PyObject *args, PyObject *kwds)
{
	PyObject *tnkey_instance;
	const char *key_type_str;

	tnkey_instance = PyObject_CallObject((PyObject *)&TNKeyType, args);
	if (tnkey_instance == NULL) {
		return -1;
	}

	key_type_str = ((py_tnkey_t *)tnkey_instance)->c_key_type_str;
	if (key_type_str == NULL || strcmp(key_type_str, KEY_TYPE_STR_KEYRING) != 0) {
		Py_DECREF(tnkey_instance);
		PyErr_SetString(PyExc_ValueError,
				"Key type must be 'keyring'");
		return -1;
	}

	self->py_key = (py_tnkey_t *)tnkey_instance;

	return 0;
}

static PyObject *
py_tn_keyring_key(py_tn_keyring_t *self, PyObject *Py_UNUSED(ignored))
{
	return Py_NewRef((PyObject *)self->py_key);
}


PyDoc_STRVAR(py_tn_keyring_clear__doc__,
"clear() -> None\n"
"---------------\n\n"
"Clear all keys from the keyring, removing all contained keys.\n"
"See man (3) keyctl_clear for more information.\n\n"
""
"Parameters\n"
"----------\n"
"None\n\n"
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
py_tn_keyring_clear(py_tn_keyring_t *self, PyObject *args)
{
	long result;

	Py_BEGIN_ALLOW_THREADS
	result = keyctl_clear(self->py_key->c_serial);
	Py_END_ALLOW_THREADS

	if (result == -1) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	Py_RETURN_NONE;
}

PyDoc_STRVAR(py_tn_keyring_iter_keyring_contents__doc__,
"iter_keyring_contents(*, unlink_expired=False, unlink_revoked=False)\n"
"    -> Iterator[truenas_keyring.TNKey | truenas_keyring.TNKeyring]\n"
"---------------------------------------------------------------------\n\n"
"Return an iterator over all keys contained within the keyring.\n"
"See man (3) keyctl_read for more information.\n\n"
""
"Parameters\n"
"----------\n"
"unlink_expired: bool, optional\n"
"    If True, automatically unlink expired keys from the keyring.\n"
"    Default: False.\n\n"
"unlink_revoked: bool, optional\n"
"    If True, automatically unlink revoked keys from the keyring.\n"
"    Default: False.\n\n"
""
"Returns\n"
"-------\n"
"Iterator[truenas_keyring.TNKey | truenas_keyring.TNKeyring]\n"
"    An iterator over key objects contained in this keyring.\n"
"    Each item is either a truenas_keyring.TNKey or truenas_keyring.TNKeyring\n"
"    depending on the type of the contained key.\n\n"
""
"Raises\n"
"------\n"
"truenas_keyring.KeyringError:\n"
"    System call failed (see errno for details).\n\n"
);

PyDoc_STRVAR(py_tn_keyring_list_keyring_contents__doc__,
"list_keyring_contents(*, unlink_expired=False, unlink_revoked=False)\n"
"    -> list[truenas_keyring.TNKey | truenas_keyring.TNKeyring]\n"
"---------------------------------------------------------------------\n\n"
"List all keys contained within the keyring.\n"
"See man (3) keyctl_read for more information.\n\n"
""
"Parameters\n"
"----------\n"
"unlink_expired: bool, optional\n"
"    If True, automatically unlink expired keys from the keyring.\n"
"    Default: False.\n\n"
"unlink_revoked: bool, optional\n"
"    If True, automatically unlink revoked keys from the keyring.\n"
"    Default: False.\n\n"
""
"Returns\n"
"-------\n"
"list[truenas_keyring.TNKey | truenas_keyring.TNKeyring]\n"
"    A list of key objects contained in this keyring.\n"
"    Each item is either a truenas_keyring.TNKey or truenas_keyring.TNKeyring\n"
"    depending on the type of the contained key.\n\n"
""
"Raises\n"
"------\n"
"truenas_keyring.KeyringError:\n"
"    System call failed (see errno for details).\n\n"
);

static PyObject *
py_tn_keyring_iter_keyring_contents(py_tn_keyring_t *self, PyObject *args, PyObject *kwargs)
{
	py_tn_keyring_iter_t *iter;
	bool success;
	static char *kwlist[] = {"unlink_expired", "unlink_revoked", NULL};
	bool del_exp = false;
	bool del_rev = false;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|$pp:iter_keyring_contents",
					 kwlist, &del_exp, &del_rev)) {
		return NULL;
	}

	iter = (py_tn_keyring_iter_t *)PyObject_CallFunction((PyObject *)&TNKeyringIterType, NULL);
	if (iter == NULL) {
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	success = get_keyring_serials(self->py_key->c_serial, &iter->keys, &iter->key_count);
	Py_END_ALLOW_THREADS

	if (!success) {
		Py_DECREF(iter);
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	iter->keyring = (py_tn_keyring_t *)Py_NewRef(self);
	iter->current_index = 0;
	iter->unlink_expired = del_exp;
	iter->unlink_revoked = del_rev;

	return (PyObject *)iter;
}

static PyObject *
py_tn_keyring_list_keyring_contents(py_tn_keyring_t *self, PyObject *args, PyObject *kwargs)
{
	size_t i, key_cnt;
	key_serial_t *keys;
	PyObject *py_list, *py_key_obj;
	bool success;
	static char *kwlist[] = {"unlink_expired", "unlink_revoked", NULL};
	bool del_exp = false;
	bool del_rev = false;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|$pp:list_keyring_contents",
					 kwlist, &del_exp, &del_rev)) {
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	success = get_keyring_serials(self->py_key->c_serial, &keys, &key_cnt);
	Py_END_ALLOW_THREADS

	if (!success) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	py_list = PyList_New(key_cnt);
	if (py_list == NULL) {
		PyMem_RawFree(keys);
		return NULL;
	}

	for (i = 0; i < key_cnt; i++) {
		/* Peek at key to see whether it's revoked */
		long ret;
		Py_BEGIN_ALLOW_THREADS
		ret = keyctl_read(keys[i], NULL, 0);
		Py_END_ALLOW_THREADS

		if (ret == -1) {
			if (errno == ENOKEY) {
				/* key was unlinked so skip */
				continue;
			} else if (((errno == EKEYEXPIRED) && del_exp) ||
				   ((errno == EKEYREVOKED) && del_rev)){
				/*
				 * key was revoked or expired and kwarg specified
				 * to delete them
				 */
				Py_BEGIN_ALLOW_THREADS
				keyctl_unlink(keys[i], self->py_key->c_serial);
				Py_END_ALLOW_THREADS
				continue;
			} else if ((errno == EKEYEXPIRED) || (errno == EKEYREVOKED)) {
				/*
				 * Don't present this key to API user since we can't
				 * use it for anything
				 */
				continue;
			}
		}

		errno = 0;

		py_key_obj = create_key_object_from_serial(keys[i], self->py_key->module_obj);
		if (py_key_obj == NULL) {
			/* potentially TOCTOU (though very unlikely) */
			if ((errno == ENOKEY) ||
			    (errno == EKEYEXPIRED) ||
			    (errno == EKEYREVOKED)) {
				PyErr_Clear();
				continue;
			}
			Py_DECREF(py_list);
			PyMem_RawFree(keys);
			return NULL;
		}
		PyList_SetItem(py_list, i, py_key_obj);
	}

	PyMem_RawFree(keys);
	return py_list;
}

PyDoc_STRVAR(py_tn_keyring_search__doc__,
"search(*, key_type, description) -> truenas_keyring.TNKey | truenas_keyring.TNKeyring\n"
"-------------------------------------------------------------------------------------\n\n"
"Search for a key within the keyring by key type and description.\n"
"See man (3) keyctl_search for more information.\n\n"
""
"Parameters\n"
"----------\n"
"key_type: str, required\n"
"    The type of key to search for (e.g., \"user\", \"keyring\").\n\n"
"description: str, required\n"
"    The description to search for.\n\n"
""
"Returns\n"
"-------\n"
"truenas_keyring.TNKey | truenas_keyring.TNKeyring\n"
"    The matching key or keyring object.\n\n"
""
"Raises\n"
"------\n"
"FileNotFoundError:\n"
"    Key not found in the keyring.\n"
"truenas_keyring.KeyringError:\n"
"    Other system call errors (see errno for details).\n\n"
);

static PyObject *
py_tn_keyring_search(py_tn_keyring_t *self, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = {"key_type", "description", NULL};
	const char *key_type_str;
	const char *description_str;
	key_serial_t found_serial;
	PyObject *key_instance;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "$ss:search",
					 kwlist, &key_type_str, &description_str)) {
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	found_serial = keyctl_search(self->py_key->c_serial, key_type_str, description_str, 0);
	Py_END_ALLOW_THREADS

	if (found_serial == -1) {
		if (errno == ENOKEY) {
			PyErr_SetString(PyExc_FileNotFoundError, "Key not found in keyring");
		} else {
			PyErr_SetFromErrno(get_keyring_error_from_module(self->py_key->module_obj));
		}
		return NULL;
	}

	key_instance = create_key_object_from_serial(found_serial, self->py_key->module_obj);

	return key_instance;
}

static PyObject *
py_tn_keyring_repr(py_tn_keyring_t *self)
{
	const char *description = self->py_key->c_describe ? self->py_key->c_describe : "";
	return PyUnicode_FromFormat("TNKeyring(serial=%d, description=\"%s\")",
				    self->py_key->c_serial, description);
}

static PyGetSetDef py_tn_keyring_getsetters[] = {
	{
		.name = "key",
		.get = (getter)py_tn_keyring_key,
		.set = NULL,
		.doc = "Reference to the TNKey object for the keyring",
		.closure = NULL
	},
	{NULL}
};

static PyMethodDef py_tn_keyring_methods[] = {
	{
		.ml_name = "clear",
		.ml_meth = (PyCFunction)py_tn_keyring_clear,
		.ml_flags = METH_NOARGS,
		.ml_doc = py_tn_keyring_clear__doc__
	},
	{
		.ml_name = "iter_keyring_contents",
		.ml_meth = (PyCFunction)py_tn_keyring_iter_keyring_contents,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tn_keyring_iter_keyring_contents__doc__
	},
	{
		.ml_name = "list_keyring_contents",
		.ml_meth = (PyCFunction)py_tn_keyring_list_keyring_contents,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tn_keyring_list_keyring_contents__doc__
	},
	{
		.ml_name = "search",
		.ml_meth = (PyCFunction)py_tn_keyring_search,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tn_keyring_search__doc__
	},
	{NULL}
};

PyTypeObject TNKeyringType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = MODULE_NAME ".TNKeyring",
	.tp_doc = "TrueNAS Keyring object",
	.tp_basicsize = sizeof(py_tn_keyring_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_init = (initproc) py_tn_keyring_init,
	.tp_dealloc = (destructor) py_tn_keyring_dealloc,
	.tp_repr = (reprfunc) py_tn_keyring_repr,
	.tp_methods = py_tn_keyring_methods,
	.tp_getset = py_tn_keyring_getsetters,
};
