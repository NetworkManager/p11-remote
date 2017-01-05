/*
 * Jacked directly from
 * https://wiki.openssl.org/index.php/1.1_API_Changes#Backward_compatibility
 */

#ifndef __OPENSSL_COMPAT_H__
#define __OPENSSL_COMPAT_H__

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static inline int
RSA_set0_key (RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
	/* If the fields n and e in r are NULL, the corresponding input
	* parameters MUST be non-NULL for n and e.  d may be
	* left NULL (in case only the public key is used).
	*/
	if (   (r->n == NULL && n == NULL)
	    || (r->e == NULL && e == NULL))
		return 0;

	if (n != NULL) {
		BN_free (r->n);
		r->n = n;
	}
	if (e != NULL) {
		BN_free (r->e);
		r->e = e;
	}
	if (d != NULL) {
		BN_free (r->d);
		r->d = d;
	}

	return 1;
}

static inline RSA_METHOD *
RSA_meth_dup (const RSA_METHOD *meth)
{
	RSA_METHOD *ret;

	ret = OPENSSL_malloc (sizeof (RSA_METHOD));

	if (ret != NULL) {
		memcpy (ret, meth, sizeof (*meth));
		ret->name = OPENSSL_strdup (meth->name);
		if (ret->name == NULL) {
			OPENSSL_free (ret);
			return NULL;
		}
	}

	return ret;
}

static inline int
RSA_meth_set1_name (RSA_METHOD *meth, const char *name)
{
	char *tmpname;

	tmpname = OPENSSL_strdup (name);
	if (tmpname == NULL) {
		return 0;
	}

	OPENSSL_free ((char *)meth->name);
	meth->name = tmpname;

	return 1;
}

static inline int
RSA_meth_set_priv_enc (RSA_METHOD *meth,
                       int (*priv_enc) (int flen, const unsigned char *from,
                                        unsigned char *to, RSA *rsa, int padding))
{
	meth->rsa_priv_enc = priv_enc;
	return 1;
}

static inline int
RSA_meth_set_priv_dec (RSA_METHOD *meth,
                       int (*priv_dec) (int flen, const unsigned char *from,
                                        unsigned char *to, RSA *rsa, int padding))
{
	meth->rsa_priv_dec = priv_dec;
	return 1;
}

static inline int
RSA_meth_set_finish (RSA_METHOD *meth, int (*finish) (RSA *rsa))
{
	meth->finish = finish;
	return 1;
}

static inline void
RSA_meth_free (RSA_METHOD *meth)
{
	if (meth != NULL) {
		OPENSSL_free ((char *)meth->name);
		OPENSSL_free (meth);
	}
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#endif /* __OPENSSL_COMPAT_H__ */
