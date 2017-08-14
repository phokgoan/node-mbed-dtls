
#include "DtlsServer.h"

#include <stdio.h>
#include <sys/time.h>

#define mbedtls_free	free
#define mbedtls_calloc	calloc
#define mbedtls_printf	printf
#define mbedtls_fprintf	fprintf

#define DFL_PSK				""
#define DFL_PSK_IDENTITY	"Client_identity"
#define DFL_PSK_LIST		NULL

using namespace node;

/*
 * Used by sni_parse and psk_parse to handle coma-separated lists
 */
#define GET_ITEM( dst )	\
	dst = p;			\
	while( *p != ',' )	\
		if( ++p > end )	\
			goto error;	\
	*p++ = '\0';

typedef struct options options;
struct options {
	const char *psk;			/* the pre-shared key						*/
	const char *psk_identity;	/* the pre-shared key identity				*/
	char *psk_list;				/* list of PSK id/key pairs for callback	*/
};

options g_opt;

#ifdef MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED

#define HEX2NUM( c )					\
		if( c >= '0' && c <= '9' )		\
			c -= '0';					\
		else if( c >= 'a' && c <= 'f' )	\
			c -= 'a' - 10;				\
		else if( c >= 'A' && c <= 'F' )	\
			c -= 'A' - 10;				\
		else							\
			return( -1 );

/*
 * Convert a hex string to bytes.
 * Return 0 on success, -1 on error.
 */
int unhexify( unsigned char *output, const char *input, size_t *olen )
{
	unsigned char c;
	size_t j;

	*olen = strlen( input );
	if( *olen % 2 != 0 || *olen / 2 > MBEDTLS_PSK_MAX_LEN )
		return( -1 );
	*olen /= 2;

	for( j = 0; j < *olen * 2; j += 2 )
	{
		c = input[j];
		HEX2NUM( c );
		output[ j / 2 ] = c << 4;

		c = input[j + 1];
		HEX2NUM( c );
		output[ j / 2 ] |= c;
	}

	return( 0 );
}

/*
 * Free a list of psk_entry's
 */
void psk_free( psk_entry *head )
{
	psk_entry *next;

	while( head != NULL )
	{
		next = head->next;
		mbedtls_free( head );
		head = next;
	}
}

/*
 * Parse a string of pairs name1,key1[,name2,key2[,...]]
 * into a usable psk_entry list.
 *
 * Modifies the input string! This is not production quality!
 */
psk_entry *psk_parse( char *psk_string )
{
	psk_entry *cur_entry = NULL, *new_entry = NULL;
	char *p = psk_string;
	char *end = p;
	char *key_hex;

	while( *end != '\0' )
		++end;
	*end = ',';

	while( p <= end )
	{
		if( ( new_entry = (psk_entry *) mbedtls_calloc( 1, sizeof( psk_entry ) ) ) == NULL )
			goto error;

		memset( new_entry, 0, sizeof( psk_entry ) );

		GET_ITEM( new_entry->name );
		GET_ITEM( key_hex );

		if( unhexify( new_entry->key, key_hex, &new_entry->key_len ) != 0 )
			goto error;

		new_entry->next = cur_entry;
		cur_entry = new_entry;
	}

	return( cur_entry );

error:
	psk_free( new_entry );
	psk_free( cur_entry );
	return( 0 );
}

/*
 * PSK callback
 */
int psk_callback( void *p_info, mbedtls_ssl_context *ssl,
					const unsigned char *name, size_t name_len )
{
	psk_entry *cur_entry = (psk_entry *) p_info;

	while( cur_entry != NULL )
	{
		if( name_len == strlen( cur_entry->name ) &&
			memcmp( name, cur_entry->name, name_len ) == 0 )
		{
			return( mbedtls_ssl_set_hs_psk( ssl, cur_entry->key, cur_entry->key_len ) );
		}

		cur_entry = cur_entry->next;
	}

	return( -1 );
}

#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

static void my_debug( void *ctx, int level,
											const char *file, int line,
											const char *str )
{
	((void) level);

	struct timeval tp;
	gettimeofday(&tp, NULL);
	long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;

	mbedtls_fprintf((FILE *) ctx, "%013ld:%s:%04d: %s", ms, file, line, str);
	fflush((FILE *) ctx);
}

Nan::Persistent<v8::FunctionTemplate> DtlsServer::constructor;

void
DtlsServer::Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target) {
	Nan::HandleScope scope;

	// Constructor
	v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(DtlsServer::New);
	constructor.Reset(ctor);
	v8::Local<v8::ObjectTemplate>	ctorInst = ctor->InstanceTemplate();
	ctorInst->SetInternalFieldCount(1);
	ctor->SetClassName(Nan::New("DtlsServer").ToLocalChecked());

	Nan::SetAccessor(ctorInst, Nan::New("handshakeTimeoutMin").ToLocalChecked(), 0, SetHandshakeTimeoutMin);

	Nan::Set(target, Nan::New("DtlsServer").ToLocalChecked(), ctor->GetFunction());
}

void DtlsServer::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	if (info.Length() < 1 ||
			!Buffer::HasInstance(info[0])) {
		return Nan::ThrowTypeError("Expecting key to be a buffer");
	}

	size_t key_len = Buffer::Length(info[0]);

	const unsigned char *key = (const unsigned char *)Buffer::Data(info[0]);

	int debug_level = 0;
	if (info.Length() > 1) {
		debug_level = info[1]->Uint32Value();
	}

	DtlsServer *server = new DtlsServer(key, key_len, debug_level);
	server->Wrap(info.This());
	info.GetReturnValue().Set(info.This());
}

DtlsServer::DtlsServer(const unsigned char *srv_key,
					size_t srv_key_len,
					int debug_level)
		: Nan::ObjectWrap() {
	int ret;
	const char *pers = "dtls_server";

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	unsigned char psk[MBEDTLS_PSK_MAX_LEN];
	size_t psk_len = 0;
	psk_info = NULL;
#endif

	mbedtls_ssl_config_init(&conf);
	mbedtls_ssl_cookie_init(&cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_init(&cache);
#endif
	mbedtls_x509_crt_init(&srvcert);
	mbedtls_pk_init(&pkey);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold(debug_level);
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	/*
	 * Unhexify the pre-shared key and parse the list if any given
	 */
	if( unhexify( psk, g_opt.psk, &psk_len ) != 0 )
	{
		mbedtls_printf( "pre-shared key not valid hex\n" );
		ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
		goto exit;
	}

	if( g_opt.psk_list != NULL )
	{
		if( ( psk_info = psk_parse( g_opt.psk_list ) ) == NULL )
		{
			mbedtls_printf( "psk_list invalid" );
			ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
			goto exit;
		}
	}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

	ret = mbedtls_pk_parse_key(&pkey,
		(const unsigned char *)srv_key,
		srv_key_len,
		NULL,
		0);
	if (ret != 0) goto exit;

	// TODO re-use node entropy and randomness
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
		mbedtls_entropy_func,
		&entropy,
		(const unsigned char *) pers,
		strlen(pers));
	if (ret != 0) goto exit;

	ret = mbedtls_ssl_config_defaults(&conf,
		MBEDTLS_SSL_IS_SERVER,
		MBEDTLS_SSL_TRANSPORT_DATAGRAM,
		MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) goto exit;

	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

	// TODO use node random number generator?
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

	ret = mbedtls_ssl_cookie_setup(&cookie_ctx,
		mbedtls_ctr_drbg_random,
		&ctr_drbg);
	if (ret != 0) goto exit;

	mbedtls_ssl_conf_dtls_cookies(&conf,
		mbedtls_ssl_cookie_write,
		mbedtls_ssl_cookie_check, 
		&cookie_ctx);
#ifdef MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED
	ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
	if (ret != 0) goto exit;
#endif

#ifdef MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED
	if( strlen( g_opt.psk ) != 0 && strlen( g_opt.psk_identity ) != 0 ) {
		ret = mbedtls_ssl_conf_psk( &conf, psk, psk_len,
							(const unsigned char *) g_opt.psk_identity,
							strlen( g_opt.psk_identity ) );
		if( ret != 0 ) {
			mbedtls_printf( "  failed\n  mbedtls_ssl_conf_psk returned -0x%04X\n\n", - ret );
			goto exit;
		}
	}

	if( g_opt.psk_list != NULL ) {
		mbedtls_ssl_conf_psk_cb( &conf, psk_callback, psk_info );
	}
#endif

	// needed for server to send CertificateRequest
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

	static int ssl_cert_types[] = { MBEDTLS_TLS_CERT_TYPE_RAW_PUBLIC_KEY, MBEDTLS_TLS_CERT_TYPE_NONE };
	mbedtls_ssl_conf_client_certificate_types(&conf, ssl_cert_types);
	mbedtls_ssl_conf_server_certificate_types(&conf, ssl_cert_types);

	// turn off server sending Certificate
	mbedtls_ssl_conf_certificate_send(&conf, MBEDTLS_SSL_SEND_CERTIFICATE_DISABLED);

	return;
exit:
	throwError(ret);
	return;
}

NAN_SETTER(DtlsServer::SetHandshakeTimeoutMin) {
	DtlsServer *server = Nan::ObjectWrap::Unwrap<DtlsServer>(info.This());
	mbedtls_ssl_conf_handshake_timeout(server->config(), value->Uint32Value(), server->config()->hs_timeout_max);
}

void DtlsServer::throwError(int ret) {
	char error_buf[100];
	mbedtls_strerror(ret, error_buf, 100);
	Nan::ThrowError(error_buf);
}

DtlsServer::~DtlsServer() {
	mbedtls_x509_crt_free( &srvcert );
	mbedtls_pk_free( &pkey );
	mbedtls_ssl_config_free( &conf );
	mbedtls_ssl_cookie_free( &cookie_ctx );
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	psk_free( psk_info );
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_free( &cache );
#endif
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
}
