#include "truenas_keyring.h"

#define TNKEY_NOVAL -2
#define TNKEY_SEPARATOR ";"

enum tnkeydescfield {
	TNKEYDESC_KEY_TYPE_NAME = 0,
	TNKEYDESC_KEY_UID,
	TNKEYDESC_KEY_GID,
	TNKEYDESC_KEY_PERM
};

static int
py_tnkey_parse_description(py_tnkey_t *self)
{
	char *token;
	char *endptr;
	int field = 0;
	unsigned long val;

	token = strtok(self->c_desc_buf, TNKEY_SEPARATOR);
	while (token != NULL && field <= TNKEYDESC_KEY_PERM) {
		switch (field) {
		case TNKEYDESC_KEY_TYPE_NAME:
			self->c_key_type_str = token;
			break;
		case TNKEYDESC_KEY_UID:
			val = strtoul(token, &endptr, 10);
			if (*endptr != '\0' || endptr == token) {
				self->c_key_uid = TNKEY_NOVAL;
			} else {
				self->c_key_uid = (uid_t)val;
			}
			break;
		case TNKEYDESC_KEY_GID:
			val = strtoul(token, &endptr, 10);
			if (*endptr != '\0' || endptr == token) {
				self->c_key_gid = TNKEY_NOVAL;
			} else {
				self->c_key_gid = (gid_t)val;
			}
			break;
		case TNKEYDESC_KEY_PERM:
			val = strtoul(token, &endptr, 16);
			if (*endptr != '\0' || endptr == token) {
				self->c_key_perm = TNKEY_NOVAL;
			} else {
				self->c_key_perm = (uint)val;
			}
			break;
		}
		field++;
		token = strtok(NULL, TNKEY_SEPARATOR);
	}

	return 0;
}

static PyObject *
py_tnkey_get_description(py_tnkey_t *self, void *closure)
{
	if (self->c_describe == NULL) {
		Py_RETURN_NONE;
	}
	return PyUnicode_FromString(self->c_describe);
}

static PyObject *
py_tnkey_get_key_type(py_tnkey_t *self, void *closure)
{
	if (self->c_key_type_str == NULL) {
		Py_RETURN_NONE;
	}
	return PyUnicode_FromString(self->c_key_type_str);
}

static PyObject *
py_tnkey_get_uid(py_tnkey_t *self, void *closure)
{
	if (self->c_key_uid == (uid_t)TNKEY_NOVAL) {
		Py_RETURN_NONE;
	}
	return Py_BuildValue("i", self->c_key_uid);
}

static PyObject *
py_tnkey_get_gid(py_tnkey_t *self, void *closure)
{
	if (self->c_key_gid == (gid_t)TNKEY_NOVAL) {
		Py_RETURN_NONE;
	}
	return Py_BuildValue("i", self->c_key_gid);
}

static PyObject *
py_tnkey_get_permissions(py_tnkey_t *self, void *closure)
{
	if (self->c_key_perm == (uint)TNKEY_NOVAL) {
		Py_RETURN_NONE;
	}
	return Py_BuildValue("I", self->c_key_perm);
}

static PyObject *
py_tnkey_get_serial(py_tnkey_t *self, void *closure)
{
	return Py_BuildValue("i", self->c_serial);
}

PyDoc_STRVAR(py_tnkey_read_data__doc__,
"read_data() -> bytes\n"
"-------------------\n\n"
"Read the data payload from the key.\n"
"See man (3) keyctl_read for more information.\n\n"
""
"Parameters\n"
"----------\n"
"None\n\n"
""
"Returns\n"
"-------\n"
"bytes\n"
"    The key's data payload as a bytes object.\n\n"
""
"Raises\n"
"------\n"
"ValueError:\n"
"    The underlying key type is \"keyring\" and so this function is not supported.\n"
"    Contents of a keyring should be retrieved via `list_keyring_contents()` method\n"
"truenas_keyring.KeyringError:\n"
"    System call failed (see errno for details).\n\n"
);

static PyObject *
py_tnkey_read_data(py_tnkey_t *self, PyObject *args)
{
	char *data;
	size_t data_len;
	PyObject *result;
	bool success;

	/* Check if this is a keyring - if so, raise ValueError */
	if (self->c_key_type_str != NULL && strcmp(self->c_key_type_str, KEY_TYPE_STR_KEYRING) == 0) {
		PyErr_SetString(PyExc_ValueError, "Cannot read data from keyring key type");
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	success = get_key_data(self->c_serial, &data, &data_len);
	Py_END_ALLOW_THREADS

	if (!success) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	result = PyBytes_FromStringAndSize(data, data_len);
	PyMem_RawFree(data);

	return result;
}

PyDoc_STRVAR(py_tnkey_set_timeout__doc__,
"set_timeout(timeout) -> None\n"
"----------------------------\n\n"
"Set a timeout on the key.\n"
"See man (3) keyctl_set_timeout for more information.\n\n"
""
"Parameters\n"
"----------\n"
"timeout : int\n"
"    Timeout in seconds from now when the key will expire.\n\n"
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
py_tnkey_set_timeout(py_tnkey_t *self, PyObject *args, PyObject *kwargs)
{
	unsigned int timeout;
	long res;
	static char *kwlist[] = {"timeout", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "I", kwlist, &timeout)) {
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	res = keyctl_set_timeout(self->c_serial, timeout);
	Py_END_ALLOW_THREADS

	if (res == -1) {
		PyErr_SetFromErrno(get_keyring_error_from_module(self->module_obj));
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *
py_tnkey_repr(py_tnkey_t *self)
{
	const char *description = self->c_describe ? self->c_describe : "";
	return PyUnicode_FromFormat("TNKey(serial=%d, description=\"%s\")",
				    self->c_serial, description);
}

static void
py_tnkey_dealloc(py_tnkey_t *self)
{
	PyMem_RawFree(self->c_desc_buf);
	Py_CLEAR(self->module_obj);
	Py_CLEAR(self->key_type);
	Py_TYPE(self)->tp_free((PyObject *) self);
}

static int
py_tnkey_init(py_tnkey_t *self, PyObject *args, PyObject *kwds)
{
	key_serial_t serial;
	PyObject *module_obj;
	char *pdesc;

	if (!PyArg_ParseTuple(args, "iO", &serial, &module_obj)) {
		return -1;
	}

	self->c_serial = serial;
	self->module_obj = Py_NewRef(module_obj);
	self->key_type = NULL;

	Py_BEGIN_ALLOW_THREADS

	self->c_desc_buf = get_key_description(serial);
	if (self->c_desc_buf != NULL) {
		/*
		 * Description has form "%s;%d;%d;%08x;%s"
		 * net items may be added in future kernels before
		 * the trailing %s (description) and so we use
		 * strrchr to reach it.
		 *
		 * c.f. man (3) keyctl_describe
		 */
		pdesc = strrchr(self->c_desc_buf, ';');
		self->c_describe = pdesc + 1;
		if (py_tnkey_parse_description(self) != 0) {
			PyMem_RawFree(self->c_desc_buf);
			self->c_desc_buf = NULL;
			self->c_describe = NULL;
		}
	}

	Py_END_ALLOW_THREADS

	if (self->c_describe == NULL) {
		PyErr_SetFromErrno(get_keyring_error_from_module(module_obj));
		return -1;
	}

	/* Set key_type from keytype_enum */
	tn_module_state_t *state = (tn_module_state_t *)PyModule_GetState(self->module_obj);
	if (state == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to get module state");
		return -1;
	}

	if (state->keytype_enum == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "Module keytype_enum is not initialized");
		return -1;
	}

	/* Use enum(value) constructor to find enum member by value */
	self->key_type = PyObject_CallFunction(state->keytype_enum, "s", self->c_key_type_str);
	if (self->key_type == NULL) {
		PyErr_Clear();  /* Clear any exception from enum lookup */
		PyErr_Format(PyExc_ValueError, "keyutils returned unexpected key type: '%s'", self->c_key_type_str);
		return -1;
	}

	return 0;
}

static PyGetSetDef py_tnkey_getsetters[] = {
	{"description", (getter)py_tnkey_get_description, NULL, "Key description", NULL},
	{"key_type", (getter)py_tnkey_get_key_type, NULL, "Key type", NULL},
	{"uid", (getter)py_tnkey_get_uid, NULL, "Key owner UID", NULL},
	{"gid", (getter)py_tnkey_get_gid, NULL, "Key owner GID", NULL},
	{"permissions", (getter)py_tnkey_get_permissions, NULL, "Key permissions", NULL},
	{"serial", (getter)py_tnkey_get_serial, NULL, "Key serial number", NULL},
	{NULL}
};

static PyMethodDef py_tnkey_methods[] = {
	{
		.ml_name = "read_data",
		.ml_meth = (PyCFunction)py_tnkey_read_data,
		.ml_flags = METH_NOARGS,
		.ml_doc = py_tnkey_read_data__doc__
	},
	{
		.ml_name = "set_timeout",
		.ml_meth = (PyCFunction)py_tnkey_set_timeout,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnkey_set_timeout__doc__
	},
	{NULL}
};

PyTypeObject TNKeyType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = MODULE_NAME ".TNKey",
	.tp_doc = "TrueNAS Key object",
	.tp_basicsize = sizeof(py_tnkey_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_init = (initproc) py_tnkey_init,
	.tp_dealloc = (destructor) py_tnkey_dealloc,
	.tp_repr = (reprfunc) py_tnkey_repr,
	.tp_methods = py_tnkey_methods,
	.tp_getset = py_tnkey_getsetters,
};
