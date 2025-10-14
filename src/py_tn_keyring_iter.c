#include "truenas_keyring.h"

static void
py_tn_keyring_iter_dealloc(py_tn_keyring_iter_t *self)
{
	Py_CLEAR(self->keyring);
	PyMem_RawFree(self->keys);
	self->keys = NULL;
	Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
py_tn_keyring_iter_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	py_tn_keyring_iter_t *self = NULL;
	self = (py_tn_keyring_iter_t *)type->tp_alloc(type, 0);
	return (PyObject *)self;
}

static PyObject *
py_tn_keyring_iter_iternext(py_tn_keyring_iter_t *self)
{
	PyObject *py_key_obj = NULL;

	/* Skip expired and revoked keys based on flags */
	while (self->current_index < self->key_count) {
		long ret;
		key_serial_t current_key = self->keys[self->current_index];
		self->current_index++;

		/* Peek at key to see whether it's revoked or expired */
		Py_BEGIN_ALLOW_THREADS
		ret = keyctl_read(current_key, NULL, 0);
		Py_END_ALLOW_THREADS

		if (ret == -1) {
			if (errno == ENOKEY) {
				/* key was unlinked so skip */
				continue;
			} else if (((errno == EKEYEXPIRED) && self->unlink_expired) ||
				   ((errno == EKEYREVOKED) && self->unlink_revoked)) {
				/*
				 * key was revoked or expired and flag specified
				 * to delete them
				 */
				Py_BEGIN_ALLOW_THREADS
				keyctl_unlink(current_key, self->keyring->py_key->c_serial);
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

		py_key_obj = create_key_object_from_serial(current_key, self->keyring->py_key->module_obj);
		if (py_key_obj == NULL) {
			/* potentially TOCTOU (though very unlikely) */
			if ((errno == ENOKEY) ||
			    (errno == EKEYEXPIRED) ||
			    (errno == EKEYREVOKED)) {
				PyErr_Clear();
				continue;
			}
			return NULL;
		}

		return py_key_obj;
	}

	/* No more keys */
	return NULL;
}

PyTypeObject TNKeyringIterType = {
	.tp_name = MODULE_NAME ".TNKeyringIter",
	.tp_doc = "TrueNAS Keyring iterator object",
	.tp_basicsize = sizeof(py_tn_keyring_iter_t),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_dealloc = (destructor) py_tn_keyring_iter_dealloc,
	.tp_new = py_tn_keyring_iter_new,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc) py_tn_keyring_iter_iternext,
};
