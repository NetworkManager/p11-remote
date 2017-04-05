/*
 * Copyright (C) 2016,2017 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *	 copyright notice, this list of conditions and the
 *	 following disclaimer.

 *     * Redistributions in binary form must reproduce the
 *	 above copyright notice, this list of conditions and
 *	 the following disclaimer in the documentation and/or
 *	 other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *	 used to endorse or promote products derived from this
 *	 software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Author: Lubomir Rintel <lkundrak@v3.sk>
 */

#include <stdio.h>
#include <alloca.h>
#include <string.h>

#include <openssl/engine.h>

#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>

#include "openssl-compat.h"

enum {
	/* wpa_supplicant uses this to fetch the certificate from a token. */
	LOAD_CERT_CTRL = ENGINE_CMD_BASE,
	/* wpas_supplicant uses this to indicate the module client asked for. */
	MODULE_PATH,
};

/* Engine-specific RSA private data. */

static int rsa_ex_idx;

struct rsa_ex {
	/* These keep the p11-kit module alive for the lifetime of a RSA
	 * instance. The module list is used when we had to pick the module
	 * from list of all managed by p11-kit, otherwise it's NULL and we
	 * release just the module we use. */
        CK_FUNCTION_LIST **modules;
        CK_FUNCTION_LIST *module;
        CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE pubkey, privkey, cert;
};

/**
 * release_modules:
 * @modules: optional module list
 * @module: a module
 *
 * Releases a reference to a modules list, or a standalone module instance
 * (if there's no list)
 */
static void
release_modules (CK_FUNCTION_LIST **modules, CK_FUNCTION_LIST *module)
{
	if (modules) {
		/* We used a local module list. */
		p11_kit_modules_finalize_and_release (modules);
	} else if (module) {
		/* We picked a particular (remote) module. */
		p11_kit_module_finalize (module);
		p11_kit_module_release (module);
	}
}

static void
rsa_ex_free (void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx,
             long argl, void *argp)
{
	struct rsa_ex *ex = ptr;
	CK_RV rv;

	if (!ex)
		return;
	if (ex->module) {
		rv = ex->module->C_CloseSession (ex->session);
		if (rv != CKR_OK)
			fprintf (stderr, "C_CloseSession: %s\n", p11_kit_strerror (rv));
	}
	release_modules (ex->modules, ex->module);
	free (ex);
}

/* RSA Callbacks. */

static int
rsa_padding_to_pkcs11_mechanism (int padding, CK_MECHANISM *mech)
{
	/* Ripped off from libp11. */
	switch (padding) {
	case RSA_PKCS1_PADDING:
		mech->mechanism = CKM_RSA_PKCS;
		break;
	case RSA_NO_PADDING:
		mech->mechanism = CKM_RSA_X_509;
		break;
	case RSA_X931_PADDING:
		mech->mechanism = CKM_RSA_X9_31;
		break;
	default:
		fprintf (stderr, "PKCS#11: Unsupported padding type\n");
		return 0;
	}

	return 1;
}

static int
rsa_priv_dec (int flen, const unsigned char *from, unsigned char *to,
              RSA *rsa, int padding)
{
	struct rsa_ex *ex = RSA_get_ex_data (rsa, rsa_ex_idx);
	CK_MECHANISM mech = { 0, };
	CK_RV rv;
	CK_ULONG tlen;

	if (!rsa_padding_to_pkcs11_mechanism (padding, &mech))
		return 0;

	tlen = RSA_size (rsa);

	rv = ex->module->C_DecryptInit (ex->session, &mech, ex->privkey);
	if (rv != CKR_OK) {
		fprintf (stderr, "C_DecryptInit: %s\n", p11_kit_strerror (rv));
		return 0;
	}

	rv = ex->module->C_Decrypt (ex->session, (unsigned char *)from, flen, to, &tlen);
	if (rv != CKR_OK) {
		fprintf (stderr, "C_Decrypt: %s\n", p11_kit_strerror (rv));
		return 0;
	}

	return tlen;
}

static int
rsa_priv_enc (int flen, const unsigned char *from, unsigned char *to,
              RSA *rsa, int padding)
{
	struct rsa_ex *ex = RSA_get_ex_data (rsa, rsa_ex_idx);
	CK_MECHANISM mech = { 0, };
	CK_RV rv;
	CK_ULONG tlen;

	if (!rsa_padding_to_pkcs11_mechanism (padding, &mech))
		return 0;

	tlen = RSA_size (rsa);

	rv = ex->module->C_SignInit (ex->session, &mech, ex->privkey);
	if (rv != CKR_OK) {
		fprintf (stderr, "C_SignInit: %s\n", p11_kit_strerror (rv));
		return 0;
	}

	rv = ex->module->C_Sign (ex->session, (unsigned char *)from, flen, to, &tlen);
	if (rv != CKR_OK) {
		fprintf (stderr, "C_Sign: %s\n", p11_kit_strerror (rv));
		return 0;
	}

	return tlen;
}

static int
rsa_finish (RSA *rsa)
{
	return 1;
}

/* Engine helpers. */

/**
 * object_of_class: look up a handle for an object of a particular class
 *                  matching given URI in a particular token session
 *
 * @module: the PKCS#11 module
 * @session: an PKCS#11 session handle
 * @uri: the p11-kit URI instance matching an object
 * @class: the PKCS#11 class of an object to look for
 * @obj: location where the handle of the matching object is put
 *
 * The function returns the first matching object and does not care if a
 * subsequent lookup attempt would yield more. The user is responsible for
 * supplying a sensible URI.
 *
 * session_for_uri() is a good way to obtain a session for a suitable token
 * given the URI.
 *
 * Returns: a non-zero value in case of a success, false otherwise.
 */
static int
object_of_class (CK_FUNCTION_LIST *module, CK_SESSION_HANDLE session, P11KitUri *uri,
                 CK_OBJECT_CLASS class, CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE_PTR attrs, attrs2;
	CK_ULONG n_attrs, n_attrs2;
	CK_ULONG cnt = 0;
	CK_RV rv;
	int i;

	/* Add or replace the class attribute with specified one. */
	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	attrs2 = alloca (sizeof (CK_ATTRIBUTE) * n_attrs + 1);
	memcpy (attrs2, attrs, sizeof (CK_ATTRIBUTE) * n_attrs);
	for (i = 0; i < n_attrs; i++) {
		if (attrs2[i].type == CKA_CLASS)
			break;
	}
	attrs2[i].type = CKA_CLASS;
	attrs2[i].pValue = &class;
	attrs2[i].ulValueLen = sizeof (class);
	n_attrs2 = i < n_attrs ? n_attrs : i;

	rv = module->C_FindObjectsInit (session, attrs2, n_attrs2);
	if (rv != CKR_OK) {
		fprintf (stderr, "C_FindObjectsInit: %s\n", p11_kit_strerror (rv));
		return 0;
	}
	rv = module->C_FindObjects (session, obj, 1, &cnt);
	if (rv != CKR_OK)
		fprintf (stderr, "C_FindObjects: %s\n", p11_kit_strerror (rv));
	rv = module->C_FindObjectsFinal (session);
	if (rv != CKR_OK)
		fprintf (stderr, "C_FindObjectsFinal: %s\n", p11_kit_strerror (rv));

	if (cnt)
		return 1;

	return 0;
}

/**
 * session_for_uri_on_module: obtain a session for token that matches given
 *                            URI on a particular module
 *
 * @module: the PKCS#11 module to use
 * @uri: matching p11-kit URI
 * @session: location where the handle for the token session is put
 *
 * Returns: a non-zero value in case of a success, false otherwise.
 */
static int
session_for_uri_on_module (CK_FUNCTION_LIST *module, P11KitUri *uri, CK_SESSION_HANDLE *session)
{

	CK_ULONG slot_count;
	CK_SLOT_ID_PTR slots;
	CK_RV rv;
	int i;

	rv = module->C_GetSlotList (CK_TRUE, NULL, &slot_count);
	if (rv != CKR_OK) {
		fprintf (stderr, "C_GetSlotList: %s\n", p11_kit_strerror (rv));
		return 0;
	}
	slots = alloca (sizeof (CK_SLOT_ID) * slot_count);
	rv = module->C_GetSlotList (CK_TRUE, slots, &slot_count);
	if (rv != CKR_OK) {
		fprintf (stderr, "C_GetSlotList: %s\n", p11_kit_strerror (rv));
		return 0;
	}

	for (i = 0; i < slot_count; i++) {
		CK_TOKEN_INFO token_info;

		rv = module->C_GetTokenInfo (slots[i], &token_info);
		if (rv != CKR_OK) {
			fprintf (stderr, "C_GetTokenInfo: %s\n", p11_kit_strerror (rv));
			return 0;
		}

		if (!p11_kit_uri_match_token_info (uri, &token_info))
			continue;

		rv = module->C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL, session);
		if (rv != CKR_OK) {
			fprintf (stderr, "C_OpenSession: %s\n", p11_kit_strerror (rv));
			continue;
		}

		return 1;
	}

	return 0;
}

/**
 * session_for_uri: obtain a session for token that matches given URI
 *
 * @modules: the list of available PKCS#11 modules
 * @uri: matching p11-kit URI
 * @session: location where the handle for the token session is put
 *
 * Returns: the module on which the session was opened or %NULL
 */
static CK_FUNCTION_LIST *
session_for_uri (CK_FUNCTION_LIST **modules, P11KitUri *uri, CK_SESSION_HANDLE *session)
{
	CK_FUNCTION_LIST *module;
	CK_RV rv;
	int i;
	int found = 0;

	if (modules == NULL)
		return 0;

	for (i = 0; modules[i]; i++) {
		CK_INFO info;

		module = modules[i];
		rv = module->C_GetInfo (&info);
		if (rv != CKR_OK) {
			fprintf (stderr, "C_GetInfo: %s\n", p11_kit_strerror (rv));
			continue;
		}

		if (!p11_kit_uri_match_module_info (uri, &info))
			continue;

		if (session_for_uri_on_module (module, uri, session)) {
			found = 1;
			break;
		}
	}

	return found ? module : NULL;
}

static CK_FUNCTION_LIST *
lookup_obj (const char *module_path, const char *uri_string,
            CK_OBJECT_CLASS class,
            CK_SESSION_HANDLE *session, CK_OBJECT_HANDLE *obj,
            CK_FUNCTION_LIST ***pmodules)
{
	CK_FUNCTION_LIST **modules = NULL;
	CK_FUNCTION_LIST *module = NULL;
	P11KitUri *uri = NULL;
	int ret;
	CK_RV rv;
	const char *pin_value;
#ifdef HAVE_P11KIT_REMOTING
	const char *p11_remote;
#endif

	uri = p11_kit_uri_new ();
	if (!uri) {
		fprintf (stderr, "p11_kit_uri_new failed\n");
		goto error;
	}

	ret = p11_kit_uri_parse (uri_string, P11_KIT_URI_FOR_OBJECT_ON_TOKEN_AND_MODULE, uri);
	if (ret) {
		fprintf (stderr, "p11_kit_uri_parse: %s\n", p11_kit_strerror (ret));
		goto error;
	}

#ifdef HAVE_P11KIT_REMOTING
	p11_remote = p11_kit_uri_get_p11_kit_remote (uri);
	if (p11_remote) {
		/* Load a remote module. */
		module = p11_kit_module_remote (p11_remote, 0);
		rv = p11_kit_module_initialize (module);
		if (rv != CKR_OK) {
			fprintf (stderr, "p11_kit_module_initialize: %s\n", p11_kit_strerror (rv));
			goto error;
		}
		if (!session_for_uri_on_module (module, uri, session)) {
			fprintf (stderr, "No remote token matched\n");
			goto error;
		}
	} else {
#endif
		/* Pick a local module. */
		modules = p11_kit_modules_load_and_initialize (0);
		module = session_for_uri (modules, uri, session);
		if (!module) {
			fprintf (stderr, "No token matched\n");
			goto error;
		}
#ifdef HAVE_P11KIT_REMOTING
	}
#endif

	pin_value = p11_kit_uri_get_pin_value (uri);
	if (pin_value) {
		rv = module->C_Login (*session, CKU_USER, (unsigned char *)pin_value, strlen (pin_value));
		if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			fprintf (stderr, "C_Login: %s\n", p11_kit_strerror (rv));
			goto logout;
		}
	}

	if (!object_of_class (module, *session, uri, class, obj)) {
		fprintf (stderr, "Object not found\n");
		goto logout;
	}

	p11_kit_uri_free (uri);
	if (pmodules)
		*pmodules = modules;
	return module;

logout:
	rv = module->C_CloseSession (*session);
	if (rv != CKR_OK)
		fprintf (stderr, "C_CloseSession: %s\n", p11_kit_strerror (rv));
error:
	release_modules (modules, module);
	if (uri)
		p11_kit_uri_free (uri);
	return NULL;
}

static EVP_PKEY *
obj_to_rsa_pk (ENGINE *engine, CK_FUNCTION_LIST **modules, CK_FUNCTION_LIST *module,
               CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privkey)
{
	struct rsa_ex *ex = NULL;
	RSA *rsa = NULL;
	EVP_PKEY *pk = NULL;
	CK_ATTRIBUTE attrs[] = {
		{.type = CKA_MODULUS,		.pValue = NULL_PTR,	.ulValueLen = 0 },
		{.type = CKA_PUBLIC_EXPONENT,	.pValue = NULL_PTR,	.ulValueLen = 0 },
	};
	CK_RV rv;

	rv = module->C_GetAttributeValue (session, privkey, attrs, 2);
	if (rv != CKR_OK) {
		fprintf (stderr, "C_GetAttributeValue: %s\n", p11_kit_strerror (rv));
		return NULL;
	}

	attrs[0].pValue = alloca (attrs[0].ulValueLen);
	attrs[1].pValue = alloca (attrs[1].ulValueLen);

	rv = module->C_GetAttributeValue (session, privkey, attrs, 2);
	if (rv != CKR_OK) {
		fprintf (stderr, "C_GetAttributeValue: %s\n", p11_kit_strerror (rv));
		return NULL;
	}

	ex = calloc (sizeof (struct rsa_ex), 1);
	if (ex == NULL) {
		perror ("calloc");
		return NULL;
	}
	ex->modules = modules;
	ex->module = module;
	ex->session = session;
	ex->privkey = privkey;

	rsa = RSA_new_method (engine);
	if (rsa == NULL) {
		fprintf (stderr, "RSA_new: %s\n", ERR_reason_error_string (ERR_get_error ()));
		goto error;
	}

	pk = EVP_PKEY_new ();
	if (pk == NULL) {
		fprintf (stderr, "EVP_PKEY_new failed\n");
		goto error;
	}

	if (!RSA_set0_key (rsa,
	                   BN_bin2bn (attrs[0].pValue, attrs[0].ulValueLen, NULL),
	                   BN_bin2bn (attrs[1].pValue, attrs[1].ulValueLen, NULL),
	                   NULL)) {
		fprintf (stderr, "RSA_set0_key: failed to set public key components.\n");
		goto error;
	}

	EVP_PKEY_set1_RSA (pk, rsa);
	RSA_set_ex_data (rsa, rsa_ex_idx, ex);
	RSA_free (rsa);

	return pk;
error:
	if (rsa)
		RSA_free (rsa);
	if (ex)
		free (ex);
	return NULL;
}

static EVP_PKEY *
obj_to_pk (ENGINE *engine, CK_FUNCTION_LIST **modules, CK_FUNCTION_LIST *module,
           CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privkey)
{
	CK_KEY_TYPE type;
	CK_ATTRIBUTE attrs[] = {
		{
			.type = CKA_KEY_TYPE,
			.pValue = &type,
			.ulValueLen = sizeof (type),
		},
	};
	CK_RV rv;

	rv = module->C_GetAttributeValue (session, privkey, attrs, 1);
	if (rv != CKR_OK) {
		fprintf (stderr, "C_GetAttributeValue: %s\n", p11_kit_strerror (rv));
		return NULL;
	}

	if (type == CKK_RSA)
		return obj_to_rsa_pk (engine, modules, module, session, privkey);

	return NULL;
}

/* Engine callbacks. */

static int engine_ex_idx;

struct engine_ex {
	char *module_path;
};

static EVP_PKEY *
engine_load_pubkey (ENGINE *engine, const char *s_key_id,
                    UI_METHOD *ui_method, void *callback_data)
{
	fprintf (stderr, "Loading a public key is not implemented.\n");
abort ();
	return NULL;
}
static EVP_PKEY *
engine_load_privkey (ENGINE *engine, const char *s_key_id,
                     UI_METHOD *ui_method, void *callback_data)
{
	struct engine_ex *ex = ENGINE_get_ex_data (engine, engine_ex_idx);
	EVP_PKEY *pk;
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST *module;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE privkey;
	CK_RV rv;

	module = lookup_obj (ex->module_path, s_key_id, CKO_PRIVATE_KEY,
	                     &session, &privkey, &modules);
	if (module == NULL)
		return NULL;

	pk = obj_to_pk (engine, modules, module, session, privkey);
	if (pk == NULL) {
		rv = module->C_CloseSession (session);
		if (rv != CKR_OK)
			fprintf (stderr, "C_CloseSession: %s\n", p11_kit_strerror (rv));
		release_modules (modules, module);
		return NULL;
	}

	return pk;
}

static int
engine_init (ENGINE *engine)
{
	return 1;
}

static int
engine_destroy (ENGINE *engine)
{
	struct engine_ex *ex = ENGINE_get_ex_data (engine, engine_ex_idx);

	if (!ex)
		return 1;

	if (ex->module_path)
		free (ex->module_path);
	free (ex);

	return 1;
}

static int
engine_finish (ENGINE *engine)
{
	return 1;
}

static X509 *
obj_to_cert (CK_FUNCTION_LIST *module, CK_SESSION_HANDLE session,
             CK_OBJECT_HANDLE certificate)
{
	CK_CERTIFICATE_TYPE type;
	CK_ATTRIBUTE attrs[] = {
		{
			.type = CKA_CERTIFICATE_TYPE,
			.pValue = &type,
			.ulValueLen = sizeof (type),
		}, {
			.type = CKA_VALUE,
			.pValue = NULL,
			.ulValueLen = 0,
		},
	};
	CK_RV rv;

	rv = module->C_GetAttributeValue (session, certificate, attrs, 2);
	if (rv != CKR_OK) {
		fprintf (stderr, "C_GetAttributeValue: %s\n", p11_kit_strerror (rv));
		return NULL;
	}

	if (type != CKC_X_509)
		return NULL;

	attrs[1].pValue = alloca (attrs[1].ulValueLen);

	rv = module->C_GetAttributeValue (session, certificate, attrs, 2);
	if (rv != CKR_OK) {
		fprintf (stderr, "C_GetAttributeValue: %s\n", p11_kit_strerror (rv));
		return NULL;
	}

	return d2i_X509 (NULL, (const unsigned char **)&attrs[1].pValue, attrs[1].ulValueLen);
}

static int
load_cert_ctrl (ENGINE *engine, int cmd, long i, void *p, void (*f) ())
{
	struct engine_ex *ex = ENGINE_get_ex_data (engine, engine_ex_idx);
	struct {
		const char *uri_string;
		X509 *cert;
	} *params = p;
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST *module;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE certificate;
	CK_RV rv;

	module = lookup_obj (ex->module_path, params->uri_string, CKO_CERTIFICATE,
	                     &session, &certificate, &modules);
	if (module == NULL)
		return 0;

	params->cert = obj_to_cert (module, session, certificate);

	rv = module->C_CloseSession (session);
	if (rv != CKR_OK)
		fprintf (stderr, "C_CloseSession: %s\n", p11_kit_strerror (rv));
	release_modules (modules, module);

	return params->cert ? 1 : 0;
}

static int
module_path (ENGINE *engine, int cmd, long i, void *p, void (*f) ())
{
	struct engine_ex *ex = ENGINE_get_ex_data (engine, engine_ex_idx);
	const char *module_path = p;

	if (!ex) {
		fprintf (stderr, "MODULE_PATH:%s: Engine not bound\n", module_path);
		return 0;
	}

	if (ex->module_path)
		free (ex->module_path);
	ex->module_path = strdup (module_path);

	return 1;
}

static int
engine_ctrl (ENGINE *engine, int cmd, long i, void *p, void (*f) ())
{
	switch (cmd) {
	case LOAD_CERT_CTRL:
		return load_cert_ctrl (engine, cmd, i, p, f);
	case MODULE_PATH:
		return module_path (engine, cmd, i, p, f);
	default:
		abort ();
	}
	return 0;
}

/* Engine open callback. */

static int
bind (ENGINE *engine, const char *id)
{
	struct engine_ex *ex;
	RSA_METHOD *rsa_method;
	static const char *engine_id = "pkcs11";
	static const char *engine_name = "p11-kit engine";
	static const ENGINE_CMD_DEFN engine_cmds[] = {
		{
			.cmd_num = LOAD_CERT_CTRL,
			.cmd_name = "LOAD_CERT_CTRL",
			.cmd_desc = "Load a certificate",
			.cmd_flags = ENGINE_CMD_FLAG_INTERNAL,
		}, {
			.cmd_num = MODULE_PATH,
			.cmd_name = "MODULE_PATH",
			.cmd_desc = "Specify a PKCS#11 module",
			.cmd_flags = ENGINE_CMD_FLAG_STRING,
		}, {
			.cmd_num = 0,
			.cmd_name = NULL,
			.cmd_desc = NULL,
			.cmd_flags = 0
		}
	};

	rsa_method = RSA_meth_dup (RSA_get_default_method ());
	RSA_meth_set1_name (rsa_method, "p11-kit");
	RSA_meth_set_priv_enc (rsa_method, rsa_priv_enc);
	RSA_meth_set_priv_dec (rsa_method, rsa_priv_dec);
	RSA_meth_set_finish (rsa_method, rsa_finish);

	if (!ENGINE_set_RSA (engine, rsa_method)) {
		fprintf (stderr, "ENGINE_set_RSA failed\n");
		return 0;
	}

	if (!ENGINE_set_id (engine, engine_id)) {
		fprintf (stderr, "ENGINE_set_id failed\n");
		return 0;
	}

	if (!ENGINE_set_name (engine, engine_name)) {
		fprintf (stderr, "ENGINE_set_name failed\n");
		return 0;
	}

	if (!ENGINE_set_init_function (engine, engine_init)) {
		fprintf (stderr, "ENGINE_set_init_function failed\n");
		return 0;
	}

	if (!ENGINE_set_destroy_function (engine, engine_destroy)) {
		fprintf (stderr, "ENGINE_set_destroy_function failed\n");
		return 0;
	}

	if (!ENGINE_set_finish_function (engine, engine_finish)) {
		fprintf (stderr, "ENGINE_set_finish_function failed\n");
		return 0;
	}

	if (!ENGINE_set_cmd_defns (engine, engine_cmds)) {
		fprintf (stderr, "ENGINE_set_cmd_defns failed\n");
		return 0;
	}

	if (!ENGINE_set_ctrl_function (engine, engine_ctrl)) {
		fprintf (stderr, "ENGINE_set_ctrl_function failed\n");
		return 0;
	}

	if (!ENGINE_set_load_privkey_function (engine, engine_load_privkey)) {
		fprintf (stderr, "ENGINE_set_load_privkey_function failed\n");
		return 0;
	}

	if (!ENGINE_set_load_pubkey_function (engine, engine_load_pubkey)) {
		fprintf (stderr, "ENGINE_set_load_pubkey_function failed\n");
		return 0;
	}

	if (!rsa_ex_idx)
		rsa_ex_idx = RSA_get_ex_new_index (0, NULL, NULL, NULL, rsa_ex_free);
	if (!engine_ex_idx)
		engine_ex_idx = ENGINE_get_ex_new_index (0, "p11-kit", NULL, NULL, NULL);

	ex = calloc (sizeof (struct engine_ex), 1);
	if (ex == NULL) {
		perror ("calloc");
		return 0;
	}
	ENGINE_set_ex_data (engine, engine_ex_idx, ex);

	return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN (bind)
IMPLEMENT_DYNAMIC_CHECK_FN ()
