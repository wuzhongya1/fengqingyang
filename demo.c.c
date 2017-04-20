/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* <DESC>
 * HTTP PUT with easy interface and read callback
 * </DESC>
 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
# include <openssl/opensslconf.h>
# include <openssl/evp.h>
//#include <openssl/ossl_typ.h>
#include <string.h>
#include <b64.h>
#include <openssl/md5.h>
#include <time.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define STRING_LENGTH_512 512
#define STRING_LENGTH_256 256
#define STRING_LENGTH_128 128
#define STRING_LENGTH_64  64
#define STRING_LENGTH_32  32
#define STRING_LENGTH_16  16
#define STRING_LENG
#define SIGNATURE_LENGTH 256

#define QINGSTOPSITE "qingstor.com"
#define QINGSTOPOBJECTSITE "pek3a.qingstor.com"
#define BUCKETNAME "fengqingyang-test"

#define DBGPRINT(fmt, args...) printf("[%s:%s]:%d "fmt, __FILE__, __func__, __LINE__, ##args)

/*
 * This example shows a HTTP PUT operation. PUTs a file given as a command
 * line argument to the URL also given on the command line.
 *
 * This example also uses its own read callback.
 *
 * Here's an article on how to setup a PUT handler for Apache:
 * http://www.apacheweek.com/features/put
 */

#if 0
static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t retcode;
	curl_off_t nread;

	/* in real-world cases, this would probably get this data differently
	 as this fread() stuff is exactly what the library already would do
	 by default internally */
	retcode = fread(ptr, size, nmemb, stream);

	nread = (curl_off_t)retcode;

	fprintf(stderr, "*** We read %" CURL_FORMAT_CURL_OFF_T
		  " bytes from file\n", nread);
	return retcode;
}
#endif

typedef struct {
	char *buf;
	unsigned int size;
} s_memory_struct, *p_memory_struct;

typedef struct {
	HMAC_CTX *hmac_ctx;
} g_enc_handle;

typedef struct {
	const EVP_MD *evp_md;
	char *key;/* supplied by user */
	int keylen;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen;
} hmac_handle, *p_hmac_handle;

typedef enum {
	USER_APPEND_DATE,
	USER_APPEND_AUTH,
} USER_APPED_OPT_T;

typedef enum {
	USER_HTTP_GET,
	USER_HTTP_PUT,
} USER_HTTP_ACTION_T;

typedef struct {
	USER_HTTP_ACTION_T action;
	unsigned char content_md5[MD5_DIGEST_LENGTH]; //need keep blank line
	char content_type[STRING_LENGTH_32];//need keep blan line
	char *date;
	char cano_header[STRING_LENGTH_256];//no need to keep blank line 
	char cano_resource[STRING_LENGTH_256];//can be nothing
} s_signature, *p_signature;

//static g_enc_handle g_code_handle;
static s_memory_struct g_memory_struct = {NULL, 0};

static int write_received_data(void *content, size_t size, size_t nmemb, void *userp)
{
	unsigned int realsize, alloc_size;
	p_memory_struct memp = (p_memory_struct)userp;	
	char *p = (char *)content;
	int i;

	realsize = size * nmemb;
	alloc_size = memp->size + realsize;

	for (i = 0; i < realsize; i++) {
		if (p[i] == '\r' && p[i+1] == '\n')
			DBGPRINT("find 'rn', pos:%d\n", i);
	}

	if ((memp->buf = (char *)realloc(memp->buf, alloc_size)) == NULL) {
		DBGPRINT("fail, malloc fail\n");
		return -1;
	}
	
	memcpy(memp->buf + memp->size, content, realsize);
	memp->size += realsize;
	
	return realsize;
}

#if 0
static int enc_func_init(void)
{
	if ((g_code_handle.hmac_ctx = HMAC_CTX_new()) == NULL) {
		DBGPRINT("fail, enc_func_init fail\n");
		return -1;
	}
	return 0;
}
#endif

static int enc_func_exec(p_hmac_handle pmac, const unsigned char *d, size_t n)
{
	unsigned char *p;
	p = HMAC(pmac->evp_md, pmac->key, pmac->keylen,
			d, n, pmac->md, &pmac->mdlen);
	if (!p) {
		DBGPRINT("fail, HMAC fail\n");
		return -1;
	}

	return 0;
}

#if 0
static int enc_func_clean(void)
{
	if (g_code_handle.hmac_ctx)
		HMAC_CTX_free(g_code_handle.hmac_ctx);
	return 0;
}
#endif

#if 0
static int hmac_test(unsigned char *mes, size_t meslen)
{
	char *key = "G9diniwiGZr5wv9r0V7cbHeXLLymPD7xnYiQPub8";
	//char *key = "7cLTmUtNp6ryKAEa0ye81PE5iVjudvmNhOsF5VR5";
	int keylen = strlen(key);
	hmac_handle hmac;
	int ret, i, total;
	char *b64;

	memset(&hmac, 0, sizeof(hmac));
	hmac.evp_md = EVP_sha256();
	hmac.key = key;
	hmac.keylen = keylen;
	ret = enc_func_exec(&hmac, mes, meslen);
	if (!ret) {
		DBGPRINT("hmac_sha256 success, mdlen=%u\n", hmac.mdlen);
		for (i = 0, total = hmac.mdlen; i < total; i++) {
			printf("%02x", hmac.md[i]);
		}
		printf("\n");
	}
	
	b64 = b64_encode(hmac.md, hmac.mdlen);
	printf("base64:%s\n", b64);
	free(b64);
	return 0;
}

static int md5_secret_content(unsigned char *content, int len)
{
	unsigned char *res = NULL;
	unsigned char md[MD5_DIGEST_LENGTH];
	int i;

	res = MD5(content, len, md);
	if (res) {
		for (i = 0; i < MD5_DIGEST_LENGTH; i++)
			printf("%02x", md[i]);
		printf("\n");
	}
	return 0;
}
#endif

static char *calc_hmac_md5(unsigned char *mes, size_t meslen)
{
	char *key = "G9diniwiGZr5wv9r0V7cbHeXLLymPD7xnYiQPub8";
	int keylen = strlen(key);
	hmac_handle hmac;
	int ret, i, total;
	char *b64;

	memset(&hmac, 0, sizeof(hmac));
	hmac.evp_md = EVP_sha256();
	hmac.key = key;
	hmac.keylen = keylen;
	ret = enc_func_exec(&hmac, mes, meslen);
	if (!ret) {
		DBGPRINT("hmac_sha256 success, mdlen=%u\n", hmac.mdlen);
		for (i = 0, total = hmac.mdlen; i < total; i++) {
			printf("%02x", hmac.md[i]);
		}
		printf("\n");
	}
	
	b64 = b64_encode(hmac.md, hmac.mdlen);
	printf("base64:%s\n", b64);
	//free(b64);
	return b64;
}

static char *format_signature(p_signature psig)
{
	int chs;
	char method[STRING_LENGTH_16];
	char string_to_sign[STRING_LENGTH_512];

	switch (psig->action) {
	case USER_HTTP_GET:
		strcpy(method, "GET");
		break;
	case USER_HTTP_PUT:
		strcpy(method, "PUT");
		break;
	default:
		break;
	}
#if 0
	chs = sprintf(string_to_sign, "%s\n"\
			"\n"\
			"\n"\
			"%s\n"\
			"/fengqingyang-test"\
			, method, psig->date);
#endif
	chs = sprintf(string_to_sign, "%s\n"\
			"\n"\
			"\n"\
			"%s\n"\
			"%s"\
			, method, psig->date, psig->cano_resource);
	printf("string_to_sign:%s\n", string_to_sign);
	return calc_hmac_md5((unsigned char *)string_to_sign, chs);
}

static int get_date_str(char *date_str, int maxlen)
{
	time_t ctime;
	struct tm *tm;
	
	time(&ctime);
	tm = gmtime(&ctime);
	strftime(date_str, maxlen, "%a, %d %b %Y %T GMT", tm);
	printf("Date: %s\n", date_str);
	
	return 0;
}

static int format_append_info(char *dest, USER_APPED_OPT_T opt, char *info, int infolen)
{
	char *access_key_id = "ZHEHHFKMXTLALDQMIQHO";
	//char *access_key_id = "BLIWSOPSQBPUYGREOTGJ";
	if (infolen >= STRING_LENGTH_512) {
		DBGPRINT("fatal, infolen=%d too large\n", infolen);
		return -1;
	}
	switch (opt) {
	case USER_APPEND_DATE:
		sprintf(dest, "Date: %s", info);
		break;
	case USER_APPEND_AUTH:
		sprintf(dest, "Authorization: QS %s:%s", access_key_id, info);
		printf("Authorization:%s\n", dest);
	default:
		break;
	}
	return 0;
}

static int set_curl_common_opt(CURL *curl, USER_HTTP_ACTION_T action, char *host)
{
	if (action == USER_HTTP_PUT)
		curl_easy_setopt(curl, CURLOPT_PUT, 1L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_HEADER, 1);
	curl_easy_setopt(curl, CURLOPT_URL, host);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_received_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &g_memory_struct);
	return 0;
}

#if 0
static int get_bucket_list(CURL *curl)
{
	char url[STRING_LENGTH_256];
	char date_str[STRING_LENGTH_128];
	struct curl_slist *list = NULL;
	s_signature signature;
	char *b64_res; //need free
	CURLcode res;
	char append[STRING_LENGTH_512];
	USER_HTTP_ACTION_T action;

	memset(&signature, 0, sizeof(signature));
	action = USER_HTTP_GET;

	/* reset curl option to default */
	curl_easy_reset(curl);
	
	strcpy(url, QINGSTOPSITE);
	set_curl_common_opt(curl, action, url);

	get_date_str(date_str, STRING_LENGTH_128);
	format_append_info(append, USER_APPEND_DATE, date_str, strlen(date_str));
	list = curl_slist_append(list, append);
	
	signature.action = action;
	signature.date = date_str;
	strcpy(signature.cano_resource,"/");
	b64_res = format_signature(&signature);
	
	format_append_info(append, USER_APPEND_AUTH, b64_res, strlen(b64_res));
	list = curl_slist_append(list, append);

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

	res = curl_easy_perform(curl);
	/* Check for errors */
	if(res != CURLE_OK)
	  fprintf(stderr, "curl_easy_perform() failed: %s\n",
			  curl_easy_strerror(res));

	curl_slist_free_all(list);
	free(b64_res);
	return 0;
}
#endif

static int get_bucket_acl(CURL *curl)
{
	char url[STRING_LENGTH_256];
	char date_str[STRING_LENGTH_128];
	struct curl_slist *list = NULL;
	s_signature signature;
	char *b64_res; //need free
	CURLcode res;
	char append[STRING_LENGTH_512];
	USER_HTTP_ACTION_T action;
	char path[STRING_LENGTH_256];

	memset(&signature, 0, sizeof(signature));
	action = USER_HTTP_GET;

	/* reset curl option to default */
	curl_easy_reset(curl);
	
	//strcpy(url, QINGSTOPSITE);
	//strcpy(path, "/%s", BUCKETNAME);
	sprintf(path, "/%s", BUCKETNAME);
	//sprintf(url, "%s%s", QINGSTOPOBJECTSITE, path);
	sprintf(url, "%s/%s", QINGSTOPOBJECTSITE, BUCKETNAME);
	set_curl_common_opt(curl, action, url);

	get_date_str(date_str, STRING_LENGTH_128);
	format_append_info(append, USER_APPEND_DATE, date_str, strlen(date_str));
	list = curl_slist_append(list, append);
	
	signature.action = action;
	signature.date = date_str;
	strcpy(signature.cano_resource, path);
	b64_res = format_signature(&signature);
	
	format_append_info(append, USER_APPEND_AUTH, b64_res, strlen(b64_res));
	list = curl_slist_append(list, append);

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

	res = curl_easy_perform(curl);
	/* Check for errors */
	if(res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
			  curl_easy_strerror(res));
		return -1;
	}
	
	printf("received data(%u):\n%s\n", g_memory_struct.size, g_memory_struct.buf);
	curl_slist_free_all(list);
	free(b64_res);
	return 0;
}

int main(int argc, char **argv)
{
	CURL *curl;
	//char *mes = "hello world\r\n";


#if 0
	enc_func_init();
	hmac_test((unsigned char *)mes, strlen(mes));
	md5_secret_content("hello world", 11);
#endif

	curl_global_init(CURL_GLOBAL_ALL);
	//g_memory_struct.buf = malloc(1);

	/* get a curl handle */
	curl = curl_easy_init();
	if (curl == NULL)
		goto cleanup;
	
	//get_bucket_list(curl);
	get_bucket_acl(curl);	

	/* always cleanup */
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	
	//enc_func_clean();
cleanup:
	return 0;
}

