#ifndef TRUENAS_KEYRING_H
#define TRUENAS_KEYRING_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <keyutils.h>
#include <stdbool.h>

#define MODULE_NAME "truenas_keyring"
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define __stringify(x) #x
#define __stringify2(x) __stringify(x)
#define __location__ __FILE__ ":" __stringify2(__LINE__)

/*
 * Macro to handle extreme error case in module. This should only be invoked
 * if an error condition is detected that would make it dangerous to continue.
 * This will call abort() and generate a corefile.
 */
#define __PYKR_ASSERT_IMPL(test, message, location) do {\
	if (!test) {\
		Py_FatalError(message " [" location "]");\
	}\
} while (0);
#define PYKR_ASSERT(test, message)\
	__PYKR_ASSERT_IMPL(test, message, __location__);

typedef struct {
	PyObject_HEAD
	key_serial_t c_serial;
	char *c_desc_buf;
	char *c_describe;
	char *c_key_type_str;
	uid_t c_key_uid;
	gid_t c_key_gid;
	uint c_key_perm;
	PyObject *module_obj;
	PyObject *key_type;
} py_tnkey_t;

typedef struct {
	PyObject_HEAD
	py_tnkey_t *py_key;
} py_tn_keyring_t;

typedef struct {
	PyObject_HEAD
	py_tn_keyring_t *keyring;
	key_serial_t *keys;
	size_t key_count;
	size_t current_index;
	bool unlink_expired;
	bool unlink_revoked;
} py_tn_keyring_iter_t;

typedef struct {
	PyObject *special_keyring_enum;
	PyObject *keytype_enum;
	PyObject *keyring_error;
} tn_module_state_t;

extern PyTypeObject TNKeyType;
extern PyTypeObject TNKeyringType;
extern PyTypeObject TNKeyringIterType;

int tn_key_add_enums_to_module(PyObject *module);

/* from py_key_utils.c */
char *get_key_description(key_serial_t serial);
bool check_key_type(key_serial_t serial, const char *key_type_str, bool *match_out);
bool get_keyring_serials(key_serial_t serial, key_serial_t **keys_out, size_t *cnt_out);
bool get_key_data(key_serial_t serial, char **data_out, size_t *data_len);
PyObject *create_key_object_from_serial(key_serial_t key_serial, PyObject *module_obj);

/* Helper function to get KeyringError from module */
PyObject *get_keyring_error_from_module(PyObject *module_obj);

#define KEY_TYPE_STR_KEYRING "keyring"
#define KEY_TYPE_STR_USER "user"
#define KEY_TYPE_STR_LOGON "logon"
#define KEY_TYPE_STR_BIGKEY "big_key"
#endif
