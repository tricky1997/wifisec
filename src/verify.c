#include "common.h"
#include "prototypes.h"




static int load_file_lookup(X509_STORE *, char *);
static int add_dir_lookup(X509_STORE *, char *);


static int verify_callback(int, X509_STORE_CTX *);
static int cert_check(CLI * c, X509_STORE_CTX *, int);
static int crl_check(CLI * c, X509_STORE_CTX *);


static void log_time(const int, const char *, ASN1_TIME *);



int verify_init(SERVICE_OPTIONS * section)
{
	if (section->verify_level < 0)
		return 0;	

	if (section->verify_level >= 2 && !section->ca_file && !section->ca_dir) {
		s_log(LOG_ERR,
		      "Either CApath or CAfile has to be used for authentication");
		return 1;	
	}

	section->revocation_store = X509_STORE_new();
	if (!section->revocation_store) {
		sslerror("X509_STORE_new");
		return 1;	
	}

	if (section->ca_file) {
		if (!SSL_CTX_load_verify_locations(section->ctx,
						   section->ca_file, NULL)) {
			s_log(LOG_ERR,
			      "Error loading verify certificates from %s",
			      section->ca_file);
			sslerror("SSL_CTX_load_verify_locations");
			return 1;	
		}
		
		SSL_CTX_set_client_CA_list(section->ctx,
					   SSL_load_client_CA_file
					   (section->ca_file));
		s_log(LOG_DEBUG, "Loaded verify certificates from %s",
		      section->ca_file);
		if (load_file_lookup
		    (section->revocation_store, section->ca_file))
			return 1;	
	}

	if (section->ca_dir) {
		if (!SSL_CTX_load_verify_locations(section->ctx,
						   NULL, section->ca_dir)) {
			s_log(LOG_ERR, "Error setting verify directory to %s",
			      section->ca_dir);
			sslerror("SSL_CTX_load_verify_locations");
			return 1;	
		}
		s_log(LOG_DEBUG, "Verify directory set to %s", section->ca_dir);
		add_dir_lookup(section->revocation_store, section->ca_dir);
	}

	if (section->crl_file)
		if (load_file_lookup
		    (section->revocation_store, section->crl_file))
			return 1;	

	if (section->crl_dir) {
		section->revocation_store->cache = 0;	
		add_dir_lookup(section->revocation_store, section->crl_dir);
	}

	SSL_CTX_set_verify(section->ctx, SSL_VERIFY_PEER |
			   (section->verify_level >=
			    2 ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0),
			   verify_callback);

	if (section->ca_dir && section->verify_level >= 3)
		s_log(LOG_INFO, "Peer certificate location %s",
		      section->ca_dir);
	return 0;		
}

static int load_file_lookup(X509_STORE * store, char *name)
{
	X509_LOOKUP *lookup;

	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	if (!lookup) {
		sslerror("X509_STORE_add_lookup");
		return 1;	
	}
	if (!X509_LOOKUP_load_file(lookup, name, X509_FILETYPE_PEM)) {
		s_log(LOG_ERR, "Failed to load %s revocation lookup file",
		      name);
		sslerror("X509_LOOKUP_load_file");
		return 1;	
	}
	s_log(LOG_DEBUG, "Loaded %s revocation lookup file", name);
	return 0;		
}

static int add_dir_lookup(X509_STORE * store, char *name)
{
	X509_LOOKUP *lookup;

	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
	if (!lookup) {
		sslerror("X509_STORE_add_lookup");
		return 1;	
	}
	if (!X509_LOOKUP_add_dir(lookup, name, X509_FILETYPE_PEM)) {
		s_log(LOG_ERR, "Failed to add %s revocation lookup directory",
		      name);
		sslerror("X509_LOOKUP_add_dir");
		return 1;	
	}
	s_log(LOG_DEBUG, "Added %s revocation lookup directory", name);
	return 0;		
}



static int verify_callback(int preverify_ok, X509_STORE_CTX * callback_ctx)
{
	
	SSL *ssl;
	CLI *c;
	X509 *cert;
	int depth;
	char *subject_name;

	
	ssl = X509_STORE_CTX_get_ex_data(callback_ctx,
					 SSL_get_ex_data_X509_STORE_CTX_idx());
	c = SSL_get_ex_data(ssl, cli_index);
	cert = X509_STORE_CTX_get_current_cert(callback_ctx);
	depth = X509_STORE_CTX_get_error_depth(callback_ctx);

	
	subject_name = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

	s_log(LOG_DEBUG, "Starting certificate verification: depth=%d, %s",
	      depth, subject_name);
	if (!cert_check(c, callback_ctx, preverify_ok)) {
		s_log(LOG_WARNING, "Certificate check failed: depth=%d, %s",
		      depth, subject_name);
		OPENSSL_free(subject_name);
		return 0;	
	}
	if (!crl_check(c, callback_ctx)) {
		s_log(LOG_WARNING, "CRL check failed: depth=%d, %s",
		      depth, subject_name);
		OPENSSL_free(subject_name);
		return 0;	
	}

	
	s_log(LOG_NOTICE, "Certificate accepted: depth=%d, %s",
	      depth, subject_name);
	OPENSSL_free(subject_name);
	return 1;		
}



static int cert_check(CLI * c, X509_STORE_CTX * callback_ctx, int preverify_ok)
{
	X509_OBJECT obj;
#if OPENSSL_VERSION_NUMBER>=0x0090700fL
	ASN1_BIT_STRING *local_key, *peer_key;
#endif
	X509 *cert;
	int depth;

	if (c->opt->verify_level < 1) {
		s_log(LOG_INFO, "CERT: Verification not enabled");
		return 1;	
	}
	cert = X509_STORE_CTX_get_current_cert(callback_ctx);
	depth = X509_STORE_CTX_get_error_depth(callback_ctx);
	if (!preverify_ok) {
		
		if (c->opt->verify_level >= 4 && depth > 0) {
			s_log(LOG_INFO, "CERT: Invalid CA certificate ignored");
			return 1;	
		} else {
			s_log(LOG_WARNING, "CERT: Verification error: %s",
			      X509_verify_cert_error_string
			      (X509_STORE_CTX_get_error(callback_ctx)));
			return 0;	
		}
	}
	if (c->opt->verify_level >= 3 && depth == 0) {
		if (X509_STORE_get_by_subject(callback_ctx, X509_LU_X509,
					      X509_get_subject_name(cert),
					      &obj) != 1) {
			s_log(LOG_WARNING,
			      "CERT: Certificate not found in local repository");
			return 0;	
		}
#if OPENSSL_VERSION_NUMBER>=0x0090700fL
		peer_key = X509_get0_pubkey_bitstr(cert);
		local_key = X509_get0_pubkey_bitstr(obj.data.x509);
		if (!peer_key || !local_key
		    || peer_key->length != local_key->length
		    || memcmp(peer_key->data, local_key->data,
			      local_key->length)) {
			s_log(LOG_WARNING, "CERT: Public keys do not match");
			return 0;	
		}
#endif
		s_log(LOG_INFO, "CERT: Locally installed certificate matched");
	}
	return 1;		
}




static int crl_check(CLI * c, X509_STORE_CTX * callback_ctx)
{
	X509_STORE_CTX store_ctx;
	X509_OBJECT obj;
	X509_NAME *subject;
	X509_NAME *issuer;
	X509 *cert;
	X509_CRL *crl;
	X509_REVOKED *revoked;
	EVP_PKEY *pubkey;
	long serial;
	int i, n, rc;
	char *cp;
	ASN1_TIME *last_update = NULL, *next_update = NULL;

	
	cert = X509_STORE_CTX_get_current_cert(callback_ctx);
	subject = X509_get_subject_name(cert);
	issuer = X509_get_issuer_name(cert);

	memset((char *)&obj, 0, sizeof obj);
	X509_STORE_CTX_init(&store_ctx, c->opt->revocation_store, NULL, NULL);
	rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &obj);
	X509_STORE_CTX_cleanup(&store_ctx);
	crl = obj.data.crl;
	if (rc > 0 && crl) {
		cp = X509_NAME_oneline(subject, NULL, 0);
		s_log(LOG_INFO, "CRL: issuer: %s", cp);
		OPENSSL_free(cp);
		last_update = X509_CRL_get_lastUpdate(crl);
		next_update = X509_CRL_get_nextUpdate(crl);
		log_time(LOG_INFO, "CRL: last update", last_update);
		log_time(LOG_INFO, "CRL: next update", next_update);

		
		pubkey = X509_get_pubkey(cert);
		if (X509_CRL_verify(crl, pubkey) <= 0) {
			s_log(LOG_WARNING, "CRL: Invalid signature");
			X509_STORE_CTX_set_error(callback_ctx,
						 X509_V_ERR_CRL_SIGNATURE_FAILURE);
			X509_OBJECT_free_contents(&obj);
			if (pubkey)
				EVP_PKEY_free(pubkey);
			return 0;	
		}
		if (pubkey)
			EVP_PKEY_free(pubkey);

		
		if (!next_update) {
			s_log(LOG_WARNING, "CRL: Invalid nextUpdate field");
			X509_STORE_CTX_set_error(callback_ctx,
						 X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
			X509_OBJECT_free_contents(&obj);
			return 0;	
		}
		if (X509_cmp_current_time(next_update) < 0) {
			s_log(LOG_WARNING,
			      "CRL: CRL Expired - revoking all certificates");
			X509_STORE_CTX_set_error(callback_ctx,
						 X509_V_ERR_CRL_HAS_EXPIRED);
			X509_OBJECT_free_contents(&obj);
			return 0;	
		}
		X509_OBJECT_free_contents(&obj);
	}

	memset((char *)&obj, 0, sizeof obj);
	X509_STORE_CTX_init(&store_ctx, c->opt->revocation_store, NULL, NULL);
	rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, issuer, &obj);
	X509_STORE_CTX_cleanup(&store_ctx);
	crl = obj.data.crl;
	if (rc > 0 && crl) {
		
		n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
		for (i = 0; i < n; i++) {
			revoked =
			    sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
			if (ASN1_INTEGER_cmp
			    (revoked->serialNumber,
			     X509_get_serialNumber(cert)) == 0) {
				serial =
				    ASN1_INTEGER_get(revoked->serialNumber);
				cp = X509_NAME_oneline(issuer, NULL, 0);
				s_log(LOG_WARNING,
				      "CRL: Certificate with serial %ld (0x%lX) "
				      "revoked per CRL from issuer %s", serial,
				      serial, cp);
				OPENSSL_free(cp);
				X509_STORE_CTX_set_error(callback_ctx,
							 X509_V_ERR_CERT_REVOKED);
				X509_OBJECT_free_contents(&obj);
				return 0;	
			}
		}
		X509_OBJECT_free_contents(&obj);
	}
	return 1;		
}

static void log_time(const int level, const char *txt, ASN1_TIME * t)
{
	char *cp;
	BIO *bio;
	int n;

	if (!t)
		return;
	bio = BIO_new(BIO_s_mem());
	if (!bio)
		return;
	ASN1_TIME_print(bio, t);
	n = BIO_pending(bio);
	cp = str_alloc(n + 1);
	n = BIO_read(bio, cp, n);
	if (n < 0) {
		BIO_free(bio);
		str_free(cp);
		return;
	}
	cp[n] = '\0';
	BIO_free(bio);
	s_log(level, "%s: %s", txt, cp);
	str_free(cp);
}


