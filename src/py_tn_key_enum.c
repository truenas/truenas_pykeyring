#include "truenas_keyring.h"

typedef struct {
	const char *name;
	int value;
} intenum_entry_t;

typedef struct {
	const char *name;
	const char *value;
} strenum_entry_t;

static const intenum_entry_t spec_keyring_tbl[] = {
	{"THREAD", KEY_SPEC_THREAD_KEYRING},
	{"PROCESS", KEY_SPEC_PROCESS_KEYRING},
	{"SESSION", KEY_SPEC_SESSION_KEYRING},
	{"USER", KEY_SPEC_USER_KEYRING},
	{"USER_SESSION", KEY_SPEC_USER_SESSION_KEYRING}
};

static const strenum_entry_t keytype_tbl[] = {
	{"KEYRING", KEY_TYPE_STR_KEYRING},
	{"USER", KEY_TYPE_STR_USER},
	{"LOGON", KEY_TYPE_STR_LOGON},
	{"BIG_KEY", KEY_TYPE_STR_BIGKEY}
};

static PyObject *
create_int_enum(PyObject *int_enum_class, const char *enum_name,
		const intenum_entry_t *entries, size_t count)
{
	PyObject *enum_dict;
	PyObject *py_enum_name;
	PyObject *result_enum;
	size_t i;

	enum_dict = PyDict_New();
	if (enum_dict == NULL) {
		return NULL;
	}

	for (i = 0; i < count; i++) {
		PyObject *py_value = Py_BuildValue("i", entries[i].value);
		if (py_value == NULL ||
		    PyDict_SetItemString(enum_dict, entries[i].name,
					 py_value) < 0) {
			Py_XDECREF(py_value);
			Py_DECREF(enum_dict);
			return NULL;
		}
		Py_DECREF(py_value);
	}

	py_enum_name = PyUnicode_FromString(enum_name);
	if (py_enum_name == NULL) {
		Py_DECREF(enum_dict);
		return NULL;
	}

	result_enum = PyObject_CallFunction(int_enum_class, "OO",
					    py_enum_name, enum_dict);

	Py_DECREF(py_enum_name);
	Py_DECREF(enum_dict);

	return result_enum;
}

static PyObject *
create_str_enum(PyObject *str_enum_class, const char *enum_name,
		const strenum_entry_t *entries, size_t count)
{
	PyObject *enum_dict;
	PyObject *py_enum_name;
	PyObject *result_enum;
	size_t i;

	enum_dict = PyDict_New();
	if (enum_dict == NULL) {
		return NULL;
	}

	for (i = 0; i < count; i++) {
		PyObject *py_value = PyUnicode_FromString(entries[i].value);
		if (py_value == NULL ||
		    PyDict_SetItemString(enum_dict, entries[i].name,
					 py_value) < 0) {
			Py_XDECREF(py_value);
			Py_DECREF(enum_dict);
			return NULL;
		}
		Py_DECREF(py_value);
	}

	py_enum_name = PyUnicode_FromString(enum_name);
	if (py_enum_name == NULL) {
		Py_DECREF(enum_dict);
		return NULL;
	}

	result_enum = PyObject_CallFunction(str_enum_class, "OO",
					    py_enum_name, enum_dict);

	Py_DECREF(py_enum_name);
	Py_DECREF(enum_dict);

	return result_enum;
}

int
tn_key_add_enums_to_module(PyObject *module)
{
	PyObject *enum_module = NULL;
	PyObject *int_enum_class = NULL;
	PyObject *str_enum_class = NULL;
	PyObject *enum_obj = NULL;
	tn_module_state_t *state;

	state = (tn_module_state_t *)PyModule_GetState(module);
	if (state == NULL) {
		goto fail;
	}

	enum_module = PyImport_ImportModule("enum");
	if (enum_module == NULL) {
		goto fail;
	}

	int_enum_class = PyObject_GetAttrString(enum_module, "IntEnum");
	if (int_enum_class == NULL) {
		goto fail;
	}

	str_enum_class = PyObject_GetAttrString(enum_module, "StrEnum");
	if (str_enum_class == NULL) {
		goto fail;
	}
	Py_CLEAR(enum_module);

	enum_obj = create_int_enum(int_enum_class,
				   "SpecialKeyring",
				   spec_keyring_tbl,
				   ARRAY_SIZE(spec_keyring_tbl));
	if (PyModule_AddObjectRef(module, "SpecialKeyring", enum_obj) < 0) {
		goto fail;
	}
	state->special_keyring_enum = Py_NewRef(enum_obj);
	Py_CLEAR(enum_obj);

	enum_obj = create_str_enum(str_enum_class,
				   "KeyType",
				   keytype_tbl,
				   ARRAY_SIZE(keytype_tbl));
	if (PyModule_AddObjectRef(module, "KeyType", enum_obj) < 0) {
		goto fail;
	}
	state->keytype_enum = Py_NewRef(enum_obj);
	Py_CLEAR(enum_obj);

	Py_CLEAR(int_enum_class);
	Py_CLEAR(str_enum_class);

	return 0;

fail:
	Py_CLEAR(enum_module);
	Py_CLEAR(int_enum_class);
	Py_CLEAR(str_enum_class);
	Py_CLEAR(enum_obj);
	return -1;
}