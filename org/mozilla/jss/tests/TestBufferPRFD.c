/*
 * Test case for Buffer PRFileDesc implementation located under the
 * org.mozilla.jss.ssl.javax package. This ensures that we can do a
 * basic SSL handshake and verify that it works alright.
 */

/* Optional, for enabling asserts */
#define DEBUG 1

/* Header file under test */
#include "BufferPRFD.h"

/* NSPR required includes */
#include <prio.h>
#include <prlog.h>
#include <prmem.h>
#include <prnetdb.h>

/* NSS includes */
#include <nss.h>
#include <ssl.h>
#include <pk11pub.h>
#include <cert.h>
#include <certdb.h>
#include <certt.h>
#include <secmod.h>
#include <sslproto.h>

/* Standard includes */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static char *return_password(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    /* Return the password passed in via arg as the password for the PKCS11
     * slot. From NSS semantics it appears that this function should allocate
     * a new copy with strdup as the caller expects to free it. */
    if (retry == PR_FALSE) {
        return strdup((char*) arg);
    } else {
        /* Since arg is static, exit on an incorrect password; otherwise,
         * we'd be stuck in an infinite loop as there's no way to change
         * the value of arg. */
        fprintf(stderr, "Error: Incorrect password!\n");
        exit(1);
    }
}

static void setup_nss_context(char *database)
{
    /* Create NSS Context to reference the given NSS DB and initialize the
     * NSS context with the database connection. */
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);

    NSSInitContext *const ctx = NSS_InitContext(database, "", "", "", NULL,
        NSS_INIT_READONLY | NSS_INIT_PK11RELOAD);
    if (ctx == NULL) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: NSPR error code %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    if (NSS_Init(database) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: NSPR error code when doing NSS_Init %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }
}

static PRFileDesc *setup_nss_client(PRFileDesc *c_nspr, char *host)
{
    /* Configure the client end of the TLS connection. */
    /* Note that most of this comes from the Fedora guide link: */
    // https://docs.fedoraproject.org/en-US/Fedora_Security_Team/1/html/Defensive_Coding/sect-Defensive_Coding-TLS-Client-NSS.html
    PRFileDesc *model = PR_NewTCPSocket();
    PRFileDesc *newfd = SSL_ImportFD(NULL, model);
    if (newfd == NULL) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: NSPR error code %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    model = newfd;
    newfd = SSL_ImportFD(model, c_nspr);
    if (newfd == NULL) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_ImportFD error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }
    c_nspr = newfd;
    PR_Close(model);

    // Reset the handshake status after importing.
    if (SSL_ResetHandshake(c_nspr, PR_FALSE) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_ResetHandshake error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }
    if (SSL_SetURL(c_nspr, host) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_SetURL error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    return c_nspr;
}

static CERTCertificate *get_cert(char *host)
{
    /* Find and return the certificate for the given host in the NSS DB;
     * this is only the public key. */

    /* Code adapted from mod_nss. */
    CERTCertList *clist;
    CERTCertListNode *cln;

    /* To do this, we have to iterate over all certs in the "user" NSS
     * database and see if any has a nickname matching the hostname. */
    clist = PK11_ListCerts(PK11CertListUser, NULL);
    for (cln = CERT_LIST_HEAD(clist); !CERT_LIST_END(cln, clist);
         cln = CERT_LIST_NEXT(cln)) {
        CERTCertificate *cert = cln->cert;
        const char *nickname = (const char*)cln->appData;

        if (!nickname) {
            nickname = cert->nickname;
        }

        if (strcmp(host, nickname) == 0) {
            printf("Found cert with nickname: %s\n", nickname);
            return cert;
        }
    }

    return NULL;
}

static SECKEYPrivateKey *get_privkey(CERTCertificate *cert, char *password)
{
    /* For the given certificate, return the matching private key. Uses
     * password as authentication to the PKCS11 database if necessary. */

    /* Code adapted from mod_nss. */
    PK11SlotInfo *slot = NULL;

    /* First get the "default" slot -- this is the slot that GenerateTestCert
     * places its certificates in. */
    slot = PK11_GetInternalKeySlot();
    if (slot == NULL) {
        printf("Error finding internal slot!\n");
        exit(2);
    }

    /* Since the JSS test suite uses a password on its database, we need a
     * shim function that returns the string. Note that this is implemented
     * in various places in NSS, but not exposed to calling applications. */
    PK11_SetPasswordFunc(return_password);

    PRInt32 rv = PK11_Authenticate(slot, PR_TRUE, password);
    if (rv != SECSuccess) {
        /* This branch won't be reached as our return_password calls exit for
         * us on an incorrect password. */
        printf("Invalid password for slot!\n");
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(3);
    }

    return PK11_FindPrivateKeyFromCert(slot, cert, NULL);
}

static PRFileDesc *setup_nss_server(PRFileDesc *s_nspr, char *host, char *password, char *nickname)
{
    /* Set up the server end of the SSL connection and find certificates. */
    /* Adapted from aforementioned Fedora developer guide and mod_nss. */
    CERTCertificate *cert = get_cert(nickname);
    if (cert == NULL) {
        printf("Failed to find certificate for host: %s\n", host);
        exit(1);
    }

    SECKEYPrivateKey *priv_key = get_privkey(cert, password);
    if (priv_key == NULL) {
        printf("Failed to find private key for certificate for host: %s\n", host);
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    PRFileDesc *model = PR_NewTCPSocket();
    PRFileDesc *newfd = SSL_ImportFD(NULL, model);
    if (newfd == NULL) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: NSPR error code %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    model = newfd;
    newfd = SSL_ImportFD(model, s_nspr);
    if (newfd == NULL) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_ImportFD error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }
    s_nspr = newfd;
    PR_Close(model);

    /* This part differs from the client side: set the certificate and
     * private key we're using. */
    if (SSL_ConfigServerCert(s_nspr, cert, priv_key, NULL, 0) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_ConfigServerCert error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    /* We need to initialize the SessionID cache, else NSS will segfault
     * because it has zero size when it tries to insert the new
     * connection into the cache... */
    SSL_ConfigServerSessionIDCache(1, 100, 100, NULL);

    // Reset the handshake status -- server end
    if (SSL_ResetHandshake(s_nspr, PR_TRUE) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_ResetHandshake error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    if (SSL_SetURL(s_nspr, host) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_SetURL error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    return s_nspr;
}

bool is_finished(PRFileDesc *c_nspr, PRFileDesc *s_nspr)
{
    /* Check whether or not the SSL Handshake has finished on both sides of
     * the connection. Since we cannot be guaranteed that the handshake was
     * successful, check whether SSL isn't off, i.e., is on or failed. */
    int c_sec_status;
    int s_sec_status;
    if (SSL_SecurityStatus(c_nspr, &c_sec_status, NULL, NULL, NULL, NULL, NULL) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_SecurityStatus error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    if (SSL_SecurityStatus(s_nspr, &s_sec_status, NULL, NULL, NULL, NULL, NULL) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_SecurityStatus error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    return c_sec_status != SSL_SECURITY_STATUS_OFF && s_sec_status != SSL_SECURITY_STATUS_OFF;
}

int main(int argc, char** argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s /path/to/nssdb password cert-nickname\n", argv[0]);
        exit(1);
    }

    setup_nss_context(argv[1]);

    /* Initialize Read/Write Buffers */
    /* In order to maintain complete control over our buffers, we need to
     * create our buffers, sizes, and pointers here. This means that the
     * PRFileDesc does nothing except hold pointers to our memory and update
     * the contents/values as it sees fit (send/recv). If instead the buffer
     * took access (or created access itself), we'd need to get access to
     * them befor giving it to NSS, as NSS wraps our PRFileDesc in one of
     * their PRFileDescs, removing our access to fd->secret. */
    j_buffer *c_read_buf = jb_alloc(2048);
    j_buffer *c_write_buf = jb_alloc(2048);

    PRFileDesc *c_nspr = newBufferPRFileDesc(c_read_buf, c_write_buf,
        (uint8_t*) "localhost", 9);

    /* Initialize Server Buffers */
    PRFileDesc *s_nspr = newBufferPRFileDesc(c_write_buf, c_read_buf,
        (uint8_t*) "localhost", 9);

    /* Set up client and server sockets with NSSL */
    char *host = "localhost";
    c_nspr = setup_nss_client(c_nspr, host);
    s_nspr = setup_nss_server(s_nspr, host, argv[2], argv[3]);

    /* In the handshake step, we blindly try to step both the client and
     * server ends of the handshake. As NSS stores the contents of what we're
     * supposed to be sending, as long as our buffers are of "reasonable"
     * size, we'll be able to step one of the two sides until something useful
     * happens. */
    printf("Trying handshake...\n");

    int count = 0;
    while (!is_finished(c_nspr, s_nspr)) {
        printf("Client Handshake:\n");
        if (SSL_ForceHandshake(c_nspr) != SECSuccess) {
            const PRErrorCode err = PR_GetError();
            if (err != PR_WOULD_BLOCK_ERROR) {
                fprintf(stderr, "error: SSL_ForceHandshake error %d: %s\n",
                    err, PR_ErrorToName(err));
                exit(1);
            }
        }

        printf("\n\nServer Handshake:\n");
        if (SSL_ForceHandshake(s_nspr) != SECSuccess) {
            const PRErrorCode err = PR_GetError();
            if (err != PR_WOULD_BLOCK_ERROR) {
                fprintf(stderr, "error: SSL_ForceHandshake error %d: %s\n",
                    err, PR_ErrorToName(err));
                exit(1);
            }
        }

        printf("\n\n");
        count += 1;
        if (count >= 40) {
            fprintf(stderr, "error: unable to make progress after %d steps!\n", count);
        }
    }

    /* Send a test message from client -> server to ensure that the connection
     * truly is ready. */
    /* Note: we don't handle E_WOULDBLOCK here as our messages are small. */
    printf("Send a message from the client to the server...\n");
    size_t buf_size = 1025;
    char *buf = calloc(buf_size, sizeof(char));
    char *buf2 = calloc(buf_size, sizeof(char));
    char *client_message = "Cooking MCs";
    char *server_message = "like a pound of bacon";

    memcpy(buf, client_message, strlen(client_message));
    PRInt32 ret = PR_Write(c_nspr, buf, strlen(buf));
    if (ret < 0) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Write error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    ret = PR_Read(s_nspr, buf2, buf_size - 1);
    if (ret < 0) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Read error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    printf("Received message from client: %s [len: %d]\n", buf2, ret);
    printf("\n\n");

    /* Send a message back to confirm we received it! */
    printf("Send a message from the server to the client...\n");
    memcpy(buf, server_message, strlen(server_message));
    ret = PR_Write(s_nspr, buf, strlen(buf));
    if (ret < 0) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Write error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    memset(buf2, 0, buf_size);
    ret = PR_Read(c_nspr, buf2, buf_size - 1);
    if (ret < 0) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Read error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    printf("Received message from client: %s [len: %d]\n", buf2, ret);

    /* Close the client and then the server end of the connection. */
    ret = PR_Shutdown(c_nspr, PR_SHUTDOWN_BOTH);
    if (ret < 0) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Shutdown client error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    ret = PR_Shutdown(s_nspr, PR_SHUTDOWN_BOTH);
    if (ret < 0) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Shutdown server error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    /* Closes the underlying POSIX file descriptors */
    PR_Close(c_nspr);
    PR_Close(s_nspr);

    /* Free the buffers and their contents */
    jb_free(c_read_buf);
    jb_free(c_write_buf);

    return 0;
}
