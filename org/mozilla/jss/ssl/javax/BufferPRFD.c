#include <nspr.h>

/* Necessary for correctly propagating E_WOULDBLOCK. */
#include <errno.h>

#include <stdlib.h>
#include <string.h>

/* Ring buffer implementation to handle read/write calls. */
#include "j_buffer.h"
#include "BufferPRFD.h"

/* This struct stores all the private data we need access to from inside our
 * PRFileDesc calls. We store the following information:
 *
 *      read_bytes -- raw buffer to read from for recv(...) calls
 *      read_capacity -- size of read_bytes buffer
 *      read_ptr -- location after the last character in the buffer;
 *                  i.e., location to place the next character if writing.
 *
 *      write_bytes -- raw buffer to write to for send(...) calls
 *      write_capacity -- size of write_bytes buffer
 *      write_ptr -- location after the last character in the buffer;
 *                   i.e., location to place the next character if writing.
 *
 *      peer_addr -- peer address info, truncated to 16 bytes
 *
 * As the read_* and write_* members should be provided by the creator, and
 * actors outside our PRFileDesc need access to this information (to add more
 * bytes to the read buffer when more data arrives for instance), we store
 * pointers and not the values themselves.
 *
 * The creator is responsible for ensuring that all data gets correctly freed
 * when the program exits; we will not free any of our pointers that were not
 * created by us.
 */
struct PRFilePrivate {
    j_buffer *read_buffer;
    j_buffer *write_buffer;

    uint8_t *peer_addr;
};

static PRDescIdentity buffer_layer_id = 0;

// This function is provided as a stub for all unimplemented calls.
static PRIntn invalidInternalCall(/* anything */)
{
    // For debugging; any invalid calls are asserted, so we can get a full
    // backtrace from the debugger and _hopefully_ we can find out which call
    // was attempted. To enable asserts, define DEBUG or FORCE_PR_ASSERT
    // before loading the NSPR headers, e.g., by using the DEBUG release type
    // during CMake configuration time.
    PR_ASSERT(!"invalidInternalCall performed!");
    return 0;
}

// This function mimics shutting down a buffer.
static PRStatus PRBufferShutdown(PRFileDesc *fd, PRIntn how)
{
    // This method has no functionality; we're a lower level under both
    // the SSLEngine and NSS's SSL context. When the application issues
    // a shutdown request, SSLEngine refuses to allow new writes (and only
    // reads until the remote party acknowledges the shutdown). All data
    // should be written into the NSS connection buffer and NSS's shutdown
    // should be called. At this point, there's nothing left for us to do:
    // there's no TCP socket we need to terminate, and we need to allow
    // any remaining buffered bytes to be written. So, the only thing we
    // can do is return success here.
    return PR_SUCCESS;
}

// This function mimics closing a buffer and frees our associated data.
static PRStatus PRBufferClose(PRFileDesc *fd)
{
    PRStatus rv = PR_SUCCESS;

    if (fd->secret != NULL) {
        // We intentionally don't free read_buffer or write_buffer; we assume
        // the caller has a copy of these data structures as well, and could
        // still be reading after the PRFileDesc is closed.
        fd->secret->read_buffer = NULL;
        fd->secret->write_buffer = NULL;

        // Free the peer address we allocated during initialiation.
        free(fd->secret->peer_addr);
        fd->secret->peer_addr = NULL;

        // Free our internal data structure.
        free(fd->secret);
        fd->secret = NULL;
    }

    PR_ASSERT(fd->identity == buffer_layer_id);
    PR_ASSERT(fd->higher == NULL);
    PR_ASSERT(fd->lower == NULL);
    fd->dtor(fd);

    return rv;
}

// Fake getting the name of the remote peer
static PRStatus PRBufferGetPeerName(PRFileDesc *fd, PRNetAddr *addr)
{
    /* getPeerName takes a PRFileDesc and modifies the PRNetAddr with the
     * name of the peer. Because of the specifics of the NSS Implementation,
     * we return whatever name was passed to us on creation; we lack a real
     * TCP socket and thus a real TCP name.
     *
     * However, we have to provide the peer name as type IPv6, else it either
     * gets mangled by the IPv4 -> IPv6 translation or a
     * PR_ADDRESS_NOT_SUPPORTED_ERROR is thrown by ssl_GetPeerInfo(...).
     */

    /* There are three main places this is called in a normal TLS connection:
     *
     *      ssl_ImportFD(...) -- where the result of this function is compared
     *                           to PR_SUCCESS to see if it is connected
     *      ssl_BeginClientHandshake(...) -- where this function sets local
     *                                       values for session resumption on
     *                                       the client
     *      ssl3_HandleClientHello(...) -- where this function sets local
     *                                     values for evaluating session
     *                                     resumption from the client.
     *
     * Because these results have to be consistent for session resumption to
     * work, we must query the internal structure and return that value.
     * Note that it isn't a security risk if an incorrect peer_addr is
     * provided to us: the other party must _also_ know the session keys for
     * this to matter.
     */

    // https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSPR/Reference/PRNetAddr
    if (fd->secret == NULL || addr == NULL) {
        return PR_FAILURE;
    }

    PRFilePrivate *internal = fd->secret;
    addr->ipv6.family = PR_AF_INET6;
    addr->ipv6.port = 0xFFFF;
    addr->ipv6.flowinfo = 0x00000000;

    // We validate that strlen(peer_addr) <= 16 on creation by truncating
    // it to 16 bytes. Thus the memcpy with strlen(...) won't overflow the
    // size of ipv6.ip.
    memset(&addr->ipv6.ip, 0, 16);
    memcpy(&addr->ipv6.ip, internal->peer_addr, 16);
    return PR_SUCCESS;
}

// Respond to send requests
static PRInt32 PRBufferSend(PRFileDesc *fd, const void *buf, PRInt32 amount,
        PRIntn flags, PRIntervalTime timeout)
{
    /* Send takes a PRFileDesc and attempts to send some amount of bytes from
     * the start of buf to the other party before timeout is reached. Because
     * we're implementing this as a buffer, copy into the buffer if there is
     * free space, else return EWOULDBLOCK.  */

    PRFilePrivate *internal = fd->secret;

    if (!jb_can_write(internal->write_buffer)) {
        /* Under correct Unix non-blocking socket semantics, if we lack data
         * to write, return a negative length and set EWOULDBLOCK. This is
         * documented in `man 2 recv`. */
        PR_SetError(PR_WOULD_BLOCK_ERROR, EWOULDBLOCK);
        return -1;
    }

    /* By checking if we can write, we ensure we don't return 0 from
     * jb_write(...); otherwise, we'd violate non-blocking socket
     * semantics. */
    return jb_write(internal->write_buffer, (const uint8_t *) buf, amount);
}

// Respond to write requests
static PRInt32 PRBufferWrite(PRFileDesc *fd, const void *buf, PRInt32 amount)
{
    /* Write is the same as Send except that it doesn't have a timeout or
     * understand flags. Since our implementation of Send is fake, pass
     * arbitrary data and use it to implement Write as well. */
    return PRBufferSend(fd, buf, amount, 0, -1);
}


// Respond to recv requests
static PRInt32 PRBufferRecv(PRFileDesc *fd, void *buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout)
{
    /* Recv takes a PRFileDesc and attempts to read some amount of bytes from
     * the start of buf to return to the caller before timeout is reached.
     * Because we're implementing this as a buffer, copy from the buffer when
     * there is something in it, else return EWOULDBLOCK. */
    PRFilePrivate *internal = fd->secret;

    if (!jb_can_read(internal->read_buffer)) {
        /* See comment in PRBufferSend about EWOULDBLOCK. */
        PR_SetError(PR_WOULD_BLOCK_ERROR, EWOULDBLOCK);
        return -1;
    }

    /* By checking if we can read, we ensure we don't return 0 from
     * jb_read(...); otherwise, we'd violate non-blocking socket
     * semantics. */
    return jb_read(internal->read_buffer, (uint8_t *) buf, amount);
}

// Respond to read requests
static PRInt32 PRBufferRead(PRFileDesc *fd, void *buf, PRInt32 amount)
{
    /* Read is the same as Recv except that it doesn't have a timeout or
     * understand flags. Since our implementation of Recv is fake, pass
     * arbitrary data and use it to implement Read as well. */
    return PRBufferRecv(fd, buf, amount, 0, -1);
}

// Fake responses to getSocketOption requests
static PRStatus PRBufferGetSocketOption(PRFileDesc *fd, PRSocketOptionData *data)
{
    /* getSocketOption takes a PRFileDesc and modifies the value field of data
     * with socket option specified in the option field. We fake responses with
     * a couple of sane defaults here:
     *
     *   non_blocking = true
     *   reuse_addr = true
     *   keep_alive = false
     *   no_delay = true
     *
     * We return valid responses to three other options:
     *
     *   max_segment = capacity of read_buffer
     *   recv_buffer_size = capacity of read buffer
     *   send_buffer_size = capacity of write buffer
     *
     * Note that all responses are "fake" in that calls to SetSocketOption will
     * not be reflected here.
     */

    if (!data || !fd) {
        return PR_FAILURE;
    }

    PRFilePrivate *internal = fd->secret;
    switch (data->option) {
    case PR_SockOpt_Nonblocking:
        data->value.non_blocking = PR_TRUE;
        return PR_SUCCESS;
    case PR_SockOpt_Reuseaddr:
        data->value.reuse_addr = PR_TRUE;
        return PR_SUCCESS;
    case PR_SockOpt_Keepalive:
        data->value.keep_alive = PR_FALSE;
        return PR_SUCCESS;
    case PR_SockOpt_NoDelay:
        data->value.no_delay = PR_TRUE;
        return PR_SUCCESS;
    case PR_SockOpt_MaxSegment:
        data->value.max_segment = jb_capacity(internal->read_buffer);
        return PR_SUCCESS;
    case PR_SockOpt_RecvBufferSize:
        data->value.recv_buffer_size = jb_capacity(internal->read_buffer);
        return PR_SUCCESS;
    case PR_SockOpt_SendBufferSize:
        data->value.send_buffer_size = jb_capacity(internal->write_buffer);
        return PR_SUCCESS;
    default:
        return PR_FAILURE;
    }
}

// Fake responses to setSocketOption
static PRStatus PRBufferSetSocketOption(PRFileDesc *fd, const PRSocketOptionData *data)
{
    /* This gives the caller control over setting socket options. It is the
     * equivalent of fcntl() with F_SETFL. In our case, O_NONBLOCK is the
     * only thing passed in, which we always return as true anyways, so
     * ignore the result. */
    return PR_SUCCESS;
}

// Create a method table with all our implemented functions
static const PRIOMethods PRIOBufferMethods = {
    PR_DESC_SOCKET_TCP,
    PRBufferClose,
    PRBufferRead,
    PRBufferWrite,
    (PRAvailableFN)invalidInternalCall,
    (PRAvailable64FN)invalidInternalCall,
    (PRFsyncFN)invalidInternalCall,
    (PRSeekFN)invalidInternalCall,
    (PRSeek64FN)invalidInternalCall,
    (PRFileInfoFN)invalidInternalCall,
    (PRFileInfo64FN)invalidInternalCall,
    (PRWritevFN)invalidInternalCall,
    (PRConnectFN)invalidInternalCall,
    (PRAcceptFN)invalidInternalCall,
    (PRBindFN)invalidInternalCall,
    (PRListenFN)invalidInternalCall,
    PRBufferShutdown,
    PRBufferRecv,
    PRBufferSend,
    (PRRecvfromFN)invalidInternalCall,
    (PRSendtoFN)invalidInternalCall,
    (PRPollFN)invalidInternalCall,
    (PRAcceptreadFN)invalidInternalCall,
    (PRTransmitfileFN)invalidInternalCall,
    (PRGetsocknameFN)invalidInternalCall,
    PRBufferGetPeerName,
    (PRReservedFN)invalidInternalCall,
    (PRReservedFN)invalidInternalCall,
    PRBufferGetSocketOption,
    PRBufferSetSocketOption,
    (PRSendfileFN)invalidInternalCall,
    (PRConnectcontinueFN)invalidInternalCall,
    (PRReservedFN)invalidInternalCall,
    (PRReservedFN)invalidInternalCall,
    (PRReservedFN)invalidInternalCall,
    (PRReservedFN)invalidInternalCall
};

/* Construct a new PRFileDesc backed by a pair of buffers. Note that these
 * should be separate buffers, but need not be unique to this PRFileDesc;
 * that is, a client and server could share (but be swapped) j_buffers.
 * The caller is expected to provide a peer_info to be used for optional
 * session resumption; this will be truncated at 16 bytes of data, and
 * extended with nulls if it is shorter. It is suggested that this be an IPv4
 * or IPv6 address. Note that this value is not used to validate the hostname
 * in any way (see SSL_SetURL to validate the peer). */
PRFileDesc *newBufferPRFileDesc(j_buffer *read_buf, j_buffer *write_buf,
    uint8_t *peer_info, size_t peer_info_len)
{
    PRFileDesc *fd;

    if (buffer_layer_id == 0) {
        buffer_layer_id = PR_GetUniqueIdentity("Buffer");
    }

    fd = PR_CreateIOLayerStub(buffer_layer_id, &PRIOBufferMethods);
    if (fd) {
        fd->secret = PR_NEW(PRFilePrivate);

        fd->secret->read_buffer = read_buf;
        fd->secret->write_buffer = write_buf;

        size_t len = peer_info_len;
        if (len > 16) { len = 16; }

        fd->secret->peer_addr = calloc(16, sizeof(uint8_t));
        memcpy(fd->secret->peer_addr, peer_info, len);
    }

    return fd;
}
