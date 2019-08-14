#include <nspr.h>

/* Necessary for correctly propagating E_WOULDBLOCK. */
#include <errno.h>

#include <stdlib.h>
#include <string.h>

/* Ring buffer implementation to handle read/write calls. */
#include "j_buffer.h"

/* Use a modern pragma guard... */
#pragma once

/* Free a Buffer-backed PRFileDesc. Note that it is usually sufficient to call
 * PR_Close(...) on the buffer instead. This is provided for completeness and
 * should not be called in a SSL context as the buffer PRFileDesc is wrapped
 * by the SSL PRFileDesc. Note that this only removes references to the
 * underlying j_buffers and does not free them; it is up to the caller to
 * do so. */
void freeBufferPRFileDesc(PRFileDesc *fd);

/* Construct a new PRFileDesc backed by a pair of buffers. Note that these
 * should be separate buffers, but need not be unique to this PRFileDesc;
 * that is, a client and server could share (but be swapped) j_buffers.
 * The caller is expected to provide a peer_info to be used for optional
 * session resumption; this will be truncated at 16 bytes of data, and
 * extended with nulls if it is shorter. It is suggested that this be an IPv4
 * or IPv6 address. Note that this value is not used to validate the hostname
 * in any way (see SSL_SetURL to validate the peer). */
PRFileDesc *newBufferPRFileDesc(j_buffer *read_buf, j_buffer *write_buf,
    uint8_t *peer_info, size_t peer_info_len);
