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
#include <assert.h>

void test_getsocketoption(PRFileDesc *fd, size_t read_buf_len,
                          size_t write_buf_len)
{
    PRSocketOptionData opt;

    memset(&opt, 0, sizeof(opt));
    opt.option = PR_SockOpt_Nonblocking;
    assert(PR_GetSocketOption(fd, &opt) == PR_SUCCESS);
    assert(opt.value.non_blocking == PR_TRUE);

    memset(&opt, 0, sizeof(opt));
    opt.option = PR_SockOpt_Reuseaddr;
    assert(PR_GetSocketOption(fd, &opt) == PR_SUCCESS);
    assert(opt.value.reuse_addr == PR_TRUE);

    memset(&opt, 0, sizeof(opt));
    opt.option = PR_SockOpt_Keepalive;
    assert(PR_GetSocketOption(fd, &opt) == PR_SUCCESS);
    assert(opt.value.keep_alive == PR_FALSE);

    memset(&opt, 0, sizeof(opt));
    opt.option = PR_SockOpt_NoDelay;
    assert(PR_GetSocketOption(fd, &opt) == PR_SUCCESS);
    assert(opt.value.no_delay == PR_TRUE);

    memset(&opt, 0, sizeof(opt));
    opt.option = PR_SockOpt_RecvBufferSize;
    assert(PR_GetSocketOption(fd, &opt) == PR_SUCCESS);
    assert(opt.value.recv_buffer_size == read_buf_len);

    memset(&opt, 0, sizeof(opt));
    opt.option = PR_SockOpt_SendBufferSize;
    assert(PR_GetSocketOption(fd, &opt) == PR_SUCCESS);
    assert(opt.value.send_buffer_size == write_buf_len);
}

void test_read_write(PRFileDesc *fd) {

}

void test_with_buffer_size(size_t read_buf_len, size_t write_buf_len)
{
    /* Initialize Read/Write Buffers */
    j_buffer *read_buf = jb_alloc(read_buf_len);
    j_buffer *write_buf = jb_alloc(write_buf_len);

    PRFileDesc *fd = newBufferPRFileDesc(read_buf, write_buf,
                                         (uint8_t *) "localhost", 9);

    test_getsocketoption(fd, read_buf_len, write_buf_len);

    PR_Close(fd);
    jb_free(read_buf);
    jb_free(write_buf);
}

int main(int argc, char** argv)
{
    if (argc != 1) {
        fprintf(stderr, "usage: %s\n", argv[0]);
        return 1;
    }

    test_with_buffer_size(1023, 1023);
    test_with_buffer_size(2048, 1023);
    test_with_buffer_size(1023, 2048);

    return 0;
}
