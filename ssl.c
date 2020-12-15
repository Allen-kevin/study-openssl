 /**
 * @file ssl.c
 * @brief SSL module
 * @author 	Wan Wenkai (wanwenkai@ict.ac.cn)
 * 			Shen Yifan (shenyifan@ict.ac.cn)
 * @date 2020.8.25
 * @version 0.1
 */
/*----------------------------------------------------------------------------*/
/* - History:
 *   1. Date: 2020.8.25
 *   	Author: Shen Yifan
 *   	Modification: create
 *   2. Date: 2020.11.27
 *      Author: wanwenkai
 *      Modification: Stable handshake version
 */
/******************************************************************************/

/**/
/*
 * +---+                                +---+
 * |...|--->read() -->BIO_write(rbio)-->|...|-->SSL_read(ssl)--->in
 * |...|                                |...|
 * |...|                                |...|
 * |...|                                |...|
 * |...|<--write(fd)<--BIO_read(wbio)<--|...|<--SSL_write(ssl)<--out
 * +---+                                +...+
 *
 *     |                                |   |                   |
 *     |<------------------------------>|   |<----------------->|
 *     |         encrypted bytes        |   |  decrypted bytes  |
 */

/* make sure to define trace_level before include! */
#ifndef TRACE_LEVEL
//	#define TRACE_LEVEL	TRACELV_DEBUG
#endif

struct qapp_context *qapp;
/******************************************************************************/
/* forward declarations */
/******************************************************************************/
#include "ssl.h"
/******************************************************************************/
/* local macros */
#define READLINE 1024
#define QUEUE_SIZE 1024
#define FIRST_N_BYTE 2
#define BIO_BUFSIZ 1500
#define TESTING
#undef TESTING
/******************************************************************************/
/* local data structures */
typedef struct low_priority {
    bool encrypt;     /* encrypt or decrypt */
    char *data;       /* payload pointer */
    int len;          /* payload len */
    int (*encrypt_decrypt)(q_SSL *q_ssl, char *data, int len);
    q_SSL *q_ssl;     /* tls context pointer */
    qstack_t qstack;  /* qingyun golbal context pointer */
    mbuf_t mbuf;      /* rte_mbuf */
    struct low_priority *next;
    struct low_priority *prev;

} qlow_t;


/* Qingyun adopts a priority method processing data packets, 
 * and low-priority data packets will be processed by a 
 * single thread At the tls level, in order to cooperate 
 * with Qingyun's priority feature, tls uses tow lock-free 
 * queues. 
 * */
struct circular_queue non_EnDecrypt_list;
struct circular_queue EnDecrypt_list;
/******************************************************************************/
/* local static functions */
static inline ssl_mgt_t
get_ssl_mgt()
{
	return get_global_ctx()->g_ssl_mgt;
}

static inline q_SSL*
get_ssl_from_stream(tcp_stream_t cur_stream)
{
	return cur_stream->ssl;
}
/******************************************************************************/
/* functions */

char *cacert = "../../qstack/src/cacert.pem";
char *privk = "../../qstack/src/privkey.pem";


static int ssl_parse_conf_test()
{
    q_ssl_mgt->ssl_config[q_ssl_mgt->ctx_num].port 
			= 80;

	q_ssl_mgt->ssl_config[q_ssl_mgt->ctx_num].servcert
			= cacert; 

	q_ssl_mgt->ssl_config[q_ssl_mgt->ctx_num].serpkey 
			= privk; 

	q_ssl_mgt->ctx_num++;

	return SUCCESS;

}

static void _init_ssl_mgt(void)
{
    int i = 0;
    q_ssl_mgt->ctx_num = 0;
    for (; i < SSL_MGT_NUM; i++) {
        q_ssl_mgt->ssl_config[i].cacert = NULL;
        q_ssl_mgt->ssl_config[i].servcert = NULL;
        q_ssl_mgt->ssl_config[i].serpkey = NULL;
    }
}


/* Encrypt plaintext data into ciphertext */
static int encrypt_data(q_SSL *q_ssl, char *data, int len)
{
    int wlen = 0;
    
    SSL_write(q_ssl->ssl, data, len);
    wlen = BIO_ctrl_pending(q_ssl->sink);
    if (unlikely(wlen <= 0)) {
        TRACE_EXCP("SSL_write failure!, len = %d\n", len);
        exit(-1);
    }
    
    BIO_read(q_ssl->sink, data, wlen);

    return wlen;
}


static int decrypt_prio(q_SSL *q_ssl, char *data, int len)
{

    int rlen = 0;
    char buf[FIRST_N_BYTE];

    rlen = BIO_write(q_ssl->sink, data, len);
    if (unlikely(rlen <= 0) || unlikely(rlen < FIRST_N_BYTE)) {
        TRACE_EXCP("BIO write failure or len invalid.\n");
        exit(-1);
    }

    memset(buf, 0, FIRST_N_BYTE);
    SSL_peek(q_ssl->ssl, buf, FIRST_N_BYTE);

    return buf[0] == 'G'? 1 : 0;
}


/* Decrypt ciphertext data into plaintext */
static int decrypt_data(q_SSL *q_ssl, char *data, int len)
{
    memset(data, 0, len);

    return SSL_read(q_ssl->ssl, data, len);
}


/* Qingyun use a thread deal with low priority packets */
static void low_prio_func()
{
    while (1) {
        /* Get node from non_EnDecrypt_list. */
        qlow_t *node =  (qlow_t *)cirq_get(&non_EnDecrypt_list);
        if (unlikely(!node)) {
            continue;
        }
        /* Deal with data include encrypt or decrypt */
        node->mbuf->payload_len = node->encrypt_decrypt(node->q_ssl, node->data, node->len);
        

        if (node->mbuf->payload_len == UINT16_MAX) {
            TRACE_EXCP(" encrypt_decrypt failure!\n");
            exit(-1);
        }
        /*Add data that had been dealed with to EnDecrypt_list.*/
        cirq_add(&EnDecrypt_list, node);
    }
}


void 
init_ssl_mgt(void)
{
    /* init ssl mgt. */
    q_ssl_mgt = (ssl_mgt_t)malloc(sizeof(struct ssl_mgt));
    _init_ssl_mgt();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
    ssl_parse_conf_test();

    /* Initialize a lock-free circular queue, use to store packet 
     * which waiting been encrypted or decrypted. */
    cirq_init(&non_EnDecrypt_list, QUEUE_SIZE);
    /* Initialize a lock-free circular queue, use to store packet 
     * which had been encrypted or decrypted, waiting been send or 
     * deal with by qingyun stack. */
    cirq_init(&EnDecrypt_list, QUEUE_SIZE);

    /* Create encrypt and decrypt thread. */
	qapp = __qstack_create_worker(CRYP_THREAD_CORE, low_prio_func, NULL);
}

/* Delete tail space */
static char *rtrim(char *str)
{
	if (NULL == str || *str == '\0')
		return str;
	
	char *p = str + strlen(str) -1;

	while (p >= str && isspace(*p)) {
		*p = '\0';
		--p;
	}

	return str;
}

/* Delete head space */
static char *ltrim(char *str)
{
	if (NULL == str || *str == '\0')
		return str;

	int len = 0;
	char *p = str;
	while (*p != '\0' && isspace(*p)) {
		++p;
		++len;
	}

	memmove(str, p, strlen(str)-len+1);

	return str;
}

/* Delete space of head and tail. */
static char *s_trim(char *str)
{
	str = rtrim(str);
	str = ltrim(str);

	return str;
}


static char* split_str(char *str, const char *substr)
{
	char *result = (char *)malloc(strlen(str)-strlen(substr));

	if (0 == strncmp(str, substr, strlen(substr))) {
		strcpy(result, str+strlen(substr));
		return result;
	}

	return NULL;
}


static int get_port(char *str)
{
	return atoi(split_str(str, "PORT = "));
}

static char *get_certi_file(char *str, const char *substr)
{
    return split_str(str, substr);
}


static void readline(char *str, FILE *fp_conf)
{
	memset(str, 0, sizeof(str));
	fgets(str, READLINE, fp_conf);
	s_trim(str);
}


int ssl_parse_conf(FILE *fp_conf)
{
    assert(fp_conf);
	if (unlikely(!fp_conf)) {
        TRACE_EXCP("fp_conf is null!\n");
		return ERROR;
    }
	
	char buf[READLINE];
	
	readline(buf, fp_conf);
    q_ssl_mgt->ssl_config[q_ssl_mgt->ctx_num].port 
			= get_port(buf);

    readline(buf, fp_conf);
    q_ssl_mgt->ssl_config[q_ssl_mgt->ctx_num].cacert
            = get_certi_file(buf, "CACERT_FILE = ");
	readline(buf, fp_conf);
	q_ssl_mgt->ssl_config[q_ssl_mgt->ctx_num].servcert
            = get_certi_file(buf, "SRVCERT_FILE = ");
	readline(buf,fp_conf);
	q_ssl_mgt->ssl_config[q_ssl_mgt->ctx_num].serpkey 
            = get_certi_file(buf, "SRVPKEY = ");
	q_ssl_mgt->ctx_num++;

	return SUCCESS;
}


static void
qssl_ctx_init(struct tcp_listener *listener, struct ssl_config_t *ssl_config)
{
    if (unlikely(!listener) || unlikely(!ssl_config)) {
        TRACE_EXCP("listener or ssl_config is null!\n");
        return;
    }

	SSL_CTX *ctx;

	ctx = SSL_CTX_new(SSLv23_server_method());

	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		goto err;
	}
#if 0	
	if (!SSL_CTX_load_verify_locations(ctx, ssl_config->cacert, NULL) 
		|| (!SSL_CTX_set_default_verify_paths(ctx))) {
		printf("cacertf err\n");
		goto err;
	}
#endif
	if (SSL_CTX_use_certificate_file(ctx, ssl_config->servcert, 
		SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		goto err;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, ssl_config->serpkey, 
		SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		goto err;
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stdout);
	    goto err;
	}
	
	q_SSL_CTX *q_ssl_ctx = (q_SSL_CTX *)malloc(sizeof(q_SSL_CTX));
	q_ssl_ctx->ssl_ctx = ctx;
	listener->ssl_ctx = q_ssl_ctx;
    
    return;

err:
    TRACE_EXCP("init err.\n");
    exit(-1);
    SSL_CTX_free(ctx);
}

static int https_inquire(uint16_t port)
{
	int i;
	int num = q_ssl_mgt->ctx_num;

	for (i = 0; i < num; i++) {
        printf("ssl port = %d, port = %d\n", q_ssl_mgt->ssl_config[i].port, port);
		if (q_ssl_mgt->ssl_config[i].port == port)
			break;
	}

	return (i == num) ? -1 : i;
}

int 
set_ssl_listener(struct tcp_listener *listener)
{
    if (unlikely(!listener)) {
        TRACE_EXCP("listener is null!\n");
        return FALSE;
    }
     
	int num = https_inquire(listener->port);
	if (num != -1) {
		qssl_ctx_init(listener, &q_ssl_mgt->ssl_config[num]);
		listener->is_ssl = true;
		return SUCCESS;
	}

	return FALSE;
}


int 
set_ssl_stream(tcp_stream_t cur_stream, q_SSL_CTX *q_ssl_ctx)
{
    if (unlikely(!cur_stream) || unlikely(!q_ssl_ctx)) {
        TRACE_EXCP("cur_stream or q_ssl_ctx is null!\n");
        return -1;
    }

	q_SSL *q_ssl = (q_SSL*)malloc(sizeof(q_SSL));
	q_ssl->ssl = SSL_new(q_ssl_ctx->ssl_ctx);
    q_ssl->handshake_state = HANDSHAKE_UNINITED;
	/* bind ssl to tcp stream */
	cur_stream->ssl = q_ssl;
	q_ssl->cur_stream = cur_stream;
	cur_stream->is_ssl = true;
    /* Not properly initialized yet */

    /* Create BIO pair */
    if (!BIO_new_bio_pair(&q_ssl->source, BIO_BUFSIZ, &q_ssl->sink, BIO_BUFSIZ)) {
        ERR_print_errors_fp(stdout);
        TRACE_EXCP("BIO_new_bio_pair error!\n");
        return -1;
    }

    assert(q_ssl->ssl);
    /* Bind ssl to one of BIO pair */
    SSL_set_bio(q_ssl->ssl, q_ssl->source, q_ssl->source);

	return 0;
}


static int q_SSL_connect()
{
    return 1;
}

static int
q_SSL_accept(q_SSL *q_ssl, int sockid, uint8_t core_id, char *ssl_ptr, int r_len)
{
    if (unlikely(!q_ssl)) {
        TRACE_EXCP("q_ssl is null!\n");
        return 0;
    }

    /* Not properly initialized yet */
    struct rte_mbuf *s_mbuf;
    int w_len = 0;
    char *payload = NULL;
    
    BIO *server = q_ssl->source;
    BIO *server_io = q_ssl->sink;

    BIO_write(server_io, ssl_ptr, r_len);
    /* Deal with the client hello from client, and response 
     * server hello. */
    SSL_accept(q_ssl->ssl);
    if ((w_len = BIO_ctrl_pending(server_io)) <= 0) {
        TRACE_EXCP("BIO_ctrl_pending error!\n");
        return 0;
    }

    /* Apply mbuf, and write data to mbuf */
    s_mbuf = io_get_wmbuf(core_id, &payload, &w_len, 1);
    assert(payload); //debug
    w_len = BIO_read(server_io, payload, 1415);
    _q_tcp_send(core_id, sockid, s_mbuf, w_len, 0);

	return 1;
}


static void put_low_priority_packet_list(q_SSL *q_ssl, qstack_t qstack, mbuf_t mbuf, char *data, int len, bool state, int (*encrypt_decrypt)())
{
    qlow_t *node = (qlow_t *)malloc(sizeof(qlow_t));

    /* Initialize node. */
    node->q_ssl = q_ssl;
    node->qstack = qstack;
    node->mbuf = mbuf;
    node->data = data;
    node->len = len;
    node->encrypt = state;
    node->encrypt_decrypt = encrypt_decrypt;
    /* put a node to lock-free circular queue. */
    cirq_add(&non_EnDecrypt_list, node);
}


static int encrypt_alert(q_SSL *q_ssl, char *data, int len)
{
    if (len != 31)
        return 0;

    int rlen = 0;
    
    rlen = BIO_write(q_ssl->sink, data, len);
    if (unlikely(rlen <= 0)) {
        TRACE_EXCP("BIO write failure!\n");
        return rlen;
    }
    printf("bio write rlen = %d\n", rlen);
    memset(data, 0, len);
    rlen = SSL_read(q_ssl->ssl, data, rlen);
    printf("rlen = %d\n", rlen);   
    SSL_write(q_ssl->ssl, data, rlen);
    rlen = BIO_ctrl_pending(q_ssl->sink);
    if (unlikely(rlen <= 0)) {
        TRACE_EXCP("SSL_write failure!\n");
        exit(-1);
    }

    BIO_read(q_ssl->sink, data, rlen);

    return 1;
}

/* Decrypt the specified first n bytes of the packet payload 
 * and determine the priority. */
static int packet_decrypto(qstack_t qstack, tcp_stream_t cur_stream, mbuf_t mbuf, char *ssl_ptr, int len)
{
    mbuf->mbuf_state = MBUF_STATE_RBUFFED;

    if (!(decrypt_prio(cur_stream->ssl, ssl_ptr, len))) {
        put_low_priority_packet_list(cur_stream->ssl, qstack, mbuf, ssl_ptr, len, 0, decrypt_data);
        /* wake up thread that deal with low priority packet.*/
        wakeup_app_thread(qapp);
        return 1;
    }

    memset(ssl_ptr, 0, len);
    mbuf->payload_len = SSL_read(cur_stream->ssl->ssl, ssl_ptr, len);
#ifdef TESTING
    TRACE_FUNC("TESTING, decrypt, high priority, msg: %s, len = %d\n", ssl_ptr, mbuf->payload_len);
#endif
    /* */
    rb_put(qstack, cur_stream, mbuf);
    raise_read_event(qstack, cur_stream, get_sys_ts(), 1);

    return 1;
}


int process_ssl_packet(qstack_t qstack, tcp_stream_t cur_stream,
		mbuf_t mbuf, char *ssl_ptr, int len)
{
    if (unlikely(!qstack) || unlikely(!cur_stream) ||unlikely(!mbuf) || unlikely(!ssl_ptr)) {
        TRACE_EXCP("qstack or cur_stream or mbuf or ssl_ptr is null!\n");
        return FALSE;
    }

    if (cur_stream->ssl->handshake_state == HANDSHAKE_UNINITED) {
        /* complete ssl handshake */
        if (unlikely(!q_SSL_accept(cur_stream->ssl, cur_stream->socket->id, qstack->stack_id, ssl_ptr, len))) {
            TRACE_EXCP("tls/ssl accept failure!\n");
            return FALSE;
        }
        cur_stream->ssl->handshake_state = HANDSHAKE_WAITING;
    } else if (cur_stream->ssl->handshake_state == HANDSHAKE_WAITING) {
        /* receive client cipher data. */
        if (unlikely(!q_SSL_accept(cur_stream->ssl, cur_stream->socket->id, qstack->stack_id, ssl_ptr, len))) {
            TRACE_EXCP("tls/ssl accept failure!\n");
            return FALSE;
        }
        cur_stream->ssl->handshake_state = HANDSHAKE_COMPLETE;
        /* Tell qingyun stack that tls hanshake has established.*/
	    raise_accept_event(qstack, cur_stream);
    } else {
        if (len == 31) {
            qssl_close(qstack->stack_id, cur_stream->ssl);
            return SUCCESS;
        }
        if (unlikely(!packet_decrypto(qstack, cur_stream, mbuf, ssl_ptr, len))) {
            TRACE_EXCP("tls/ssl decrypt failure!\n");
            return FALSE;
        }
    }

    return SUCCESS;
}


/* Encrypt data which from qingyun stack */
int ssl_write(q_SSL *q_ssl, int core_id, mbuf_t mbuf, char *data, int len)
{
    if (q_ssl == NULL || mbuf == NULL || data == NULL) {
        TRACE_FUNC("q_ssl or mbuf or data is empty!\n");
        return ERROR;    
    }

    int socket_id = q_ssl->cur_stream->socket->id;
	qstack_t qstack = q_ssl->cur_stream->qstack;

    if (!mbuf->priority) {
        /* encrypt high priority packet. */
        mbuf->payload_len = encrypt_data(q_ssl, data, len);
        //assert(mbuf->payload_len == 478);
        _q_tcp_send(core_id, socket_id, mbuf, mbuf->payload_len, 0);

    } else {
        /* deal with low priority packet. */
        put_low_priority_packet_list(q_ssl, qstack, mbuf, data, len, 1, encrypt_data);
        /* wake up thread that deal with low priority packet.*/
        wakeup_app_thread(qapp);

        return FAILED; 
    }
    
    return len;
}


void handle_cryption_rsp(qstack_t qstack)
{
    qlow_t *node = (qlow_t *)cirq_get(&EnDecrypt_list);
    
    while (node != NULL) {
        if (node->encrypt) {
            //assert(node->mbuf->payload_len == 478);
            _q_tcp_send(node->qstack->stack_id, node->q_ssl->cur_stream->socket->id, node->mbuf, node->mbuf->payload_len, 0);
        } else {
            rb_put(node->qstack, node->q_ssl->cur_stream, node->mbuf);
            raise_read_event(node->qstack, node->q_ssl->cur_stream, get_sys_ts(), 1);
        }

        node = (qlow_t *)cirq_get(&EnDecrypt_list);
    };

    return SUCCESS;
}


/* free tls/ssl connection */
int qssl_close(int core_id, q_SSL *q_ssl)
{
    if (!q_ssl)
        return SUCCESS;
#if 0
    int w_len = 0;
    char *payload = NULL;
    struct rte_mbuf *s_mbuf;

    SSL_shutdown(q_ssl->ssl);
    w_len = BIO_ctrl_pending(q_ssl->sink);
    if (unlikely(w_len <= 0)) {
        TRACE_EXCP("SSL_write failure!\n");
        return 0;
    }
  /* Apply mbuf, and write data to mbuf */
    s_mbuf = io_get_wmbuf(core_id, &payload, &w_len, 1);
    assert(payload); //debug
    w_len = BIO_read(q_ssl->sink, payload, 1415);

    _q_tcp_send(core_id, q_ssl->cur_stream->socket->id, s_mbuf, w_len, 0);
#endif
    SSL_free(q_ssl->ssl);
    free(q_ssl);

    return SUCCESS;
}

/******************************************************************************/
/*----------------------------------------------------------------------------*/
