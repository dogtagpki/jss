package org.mozilla.jss.ssl.javax;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.security.*;
import java.util.*;

import javax.net.ssl.*;

/**
 * SSL-enabled SocketChannel following the javax.net.ssl.SSLSocket interface.
 *
 * This class should never be constructed directly and instead only accessed
 * once a Socket is wrapped in a JSSSocket.
 *
 * This class contains all low-level interactions with the underlying
 * SSLEngine and reading/writing to/from the underlying Socket.
 */
public class JSSSocketChannel extends SocketChannel {
    private JSSSocket sslSocket;
    private SocketChannel parent;
    private Socket parentSocket;
    private ReadableByteChannel readChannel;
    private WritableByteChannel writeChannel;
    private JSSEngine engine;

    private InputStream consumed;
    private ReadableByteChannel consumedChannel;

    private boolean autoClose = true;

    private boolean inboundClosed = false;
    private boolean outboundClosed = false;

    private ByteBuffer empty = ByteBuffer.allocate(0);
    private ByteBuffer readBuffer;
    private ByteBuffer writeBuffer;

    private boolean handshakeCompleted = false;

    public JSSSocketChannel(JSSSocket sslSocket, SocketChannel parent, Socket parentSocket, ReadableByteChannel readChannel, WritableByteChannel writeChannel, JSSEngine engine) throws IOException {
        super(null);

        this.sslSocket = sslSocket;
        this.parent = parent;
        this.parentSocket = parentSocket;
        this.readChannel = readChannel;
        this.writeChannel = writeChannel;
        this.engine = engine;

        this.readBuffer = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
        this.writeBuffer = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
    }

    public JSSSocketChannel(JSSSocket sslSocket, SocketChannel parent, JSSEngine engine) throws IOException {
        this(sslSocket, parent, parent.socket(), parent, parent, engine);

        // Copy the blocking mode from the parent channel.
        configureBlocking(parent.isBlocking());
    }

    public JSSSocketChannel(JSSSocket sslSocket, Socket parentSocket, ReadableByteChannel readChannel, WritableByteChannel writeChannel, JSSEngine engine) throws IOException {
        this(sslSocket, null, parentSocket, readChannel, writeChannel, engine);

        // When there is no parent channel, this channel must be in
        // blocking mode.
        configureBlocking(true);
    }

    /**
     * Give data already consumed by a call to the underlying socket's read
     * method to this Socket, allowing it to be read by the SSLEngine.
     */
    public void setConsumedData(InputStream consumed) throws IOException {
        if (consumed != null && consumed.available() > 0) {
            this.consumed = consumed;
            consumedChannel = Channels.newChannel(consumed);
        }
    }

    /**
     * Set whether or not to close the underlying Socket when the SSLSocket
     * or this channel is closed.
     */
    public void setAutoClose(boolean on) {
        autoClose = on;
    }

    private int remoteRead() throws IOException {
        if (consumed != null) {
            int n = consumedChannel.read(readBuffer);
            if (n < 0) {
                consumed = null;
                consumedChannel = null;
                return 0;
            }
            return n;
        } else if (isBlocking()) {
            // blocking channel; we have to bound the read to what is available
            ByteBuffer slice = readBuffer.slice();
            int available = parentSocket.getInputStream().available();
            if (slice.limit() > available)
                slice.limit(available);
            int n = readChannel.read(slice);
            readBuffer.position(readBuffer.position() + Math.max(n, 0));
            return n;
        } else {
            // non-blocking; read whatever is available
            return readChannel.read(readBuffer);
        }
    }

    public boolean finishConnect() throws IOException {
        if (parent != null) {
            if (!parent.finishConnect()) {
                return false;
            }
        }

        SSLEngineResult.HandshakeStatus state = engine.getHandshakeStatus();
        if (state == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            return true;
        }

        int handshakeAttempts = 0;
        int maxHandshakeAttempts = 100;

        if (!isBlocking()) {
            // When we're a non-blocking socket/channel, we'd far rather
            // return false than take too much time in this method. Most
            // handshakes, if all data is available, should only take
            // a couple of passes.
            maxHandshakeAttempts = 10;
        }

        // Attempt to handshake with the remote peer.
        try {
            do {
                if (state == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    // Write from an empty buffer to wrap.
                    write(empty);
                } else if (state == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                    // Read into an empty buffer to unwrap.
                    read(empty);
                } else if (state == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    // Run the task, synchronously, because we're a mostly
                    // blocking SSLSocket.
                    Runnable task = engine.getDelegatedTask();
                    task.run();
                } else {
                    String msg = "Error attempting to handshake: unknown ";
                    msg += "handshake status code `" + state + "`";
                    throw new IOException(msg);
                }

                SSLEngineResult.HandshakeStatus last_state = state;
                state = engine.getHandshakeStatus();
                handshakeAttempts += 1;

                if (state == last_state) {
                    try {
                        // This sleep is necessary in order to wait for
                        // incoming data. If it turns out our
                        // NEED_UNWRAP is premature (and we're stuck in
                        // a blocking read() call because we issued a
                        // non-zero read!), we might cause the remote
                        // peer to timeout and send a CLOSE_NOTIFY
                        // alert. This wouldn't be good, so sleep
                        // instead. Use an linear backoff in case
                        // the remote server is really slow.
                        Thread.sleep(handshakeAttempts * 10);
                    } catch (Exception e) {}
                }

                if (handshakeAttempts > maxHandshakeAttempts) {
                    if (!isBlocking()) {
                        // In the event we failed to connect under a
                        // non-blocking socket, return false rather than fail
                        // here. It could just be that we don't have enough
                        // data to continue. In that case, doHandshake() in
                        // JSSSocket will re-try until the connection succeeds.
                        return false;
                    }

                    String msg = "Error attempting to handshake: unable to ";
                    msg += "complete handshake successfully in ";
                    msg += maxHandshakeAttempts + " calls to wrap or unwrap. ";
                    msg += "Connection stalled.";
                    throw new IOException(msg);
                }
            } while (state != SSLEngineResult.HandshakeStatus.FINISHED && state != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING);
        } catch (SSLException ssle) {
            String msg = "Error attempting to handshake with remote peer: ";
            msg += "got unexpected exception: " + ssle.getMessage();
            throw new IOException(msg, ssle);
        }

        handshakeCompleted = true;
        sslSocket.notifyHandshakeCompletedListeners();

        return true;
    }

    /**
     * Compute the total size of a list of buffers from the specified offest
     * and length.
     */
    private static long computeSize(ByteBuffer[] buffers, int offset, int length) throws IOException {
        long result = 0;

        if (buffers == null || buffers.length == 0) {
            return result;
        }

        for (int rel_index = 0; rel_index < length; rel_index++) {
            int index = offset + rel_index;
            if (index >= buffers.length) {
                String msg = "Offset (" + offset + " or length (" + length;
                msg += ") exceeds contract based on number of buffers ";
                msg += "given (" + buffers.length + ")";
                throw new IOException(msg);
            }

            if (buffers[index] != null) {
                result += buffers[index].remaining();
            }
        }

        return result;
    }

    public int read(ByteBuffer dst) throws IOException {
        return (int) read(new ByteBuffer[] { dst });
    }

    public synchronized long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        if (inboundClosed) {
            return -1;
        }

        long unwrapped = 0;
        long decrypted = 0;

        try {
            SSLEngineResult result;
            do {
                int n = remoteRead();

                if (readBuffer.position() == 0) {
                    // We didn't read anything and there is no left-over data.
                    // If handshake already completed, we can continue because
                    // there may be data in the unwrapped buffer FD that has yet
                    // to be delivered to the application.
                    //
                    // But if we did not finish the handshake and there were no
                    // new data, we have to return here.  Calling unwrap() with
                    // no data, prior to handshake completion, causes the
                    // handshake to never complete.  This might be a bug, but
                    // for now we have this workaround.
                    //
                    // Note we cannot call engine.getHandshakeStatus() to perform
                    // this check; it is NOT a passive routine and reading it
                    // early triggers the same failure.
                    //
                    if (!handshakeCompleted) {
                        return decrypted > 0 ? decrypted : n;
                    }
                }

                readBuffer.flip();

                result = engine.unwrap(readBuffer, dsts, offset, length);
                switch (result.getStatus()) {
                    case CLOSED:
                        shutdownInput();
                    case OK:
                    case BUFFER_UNDERFLOW:
                        break; // CLOSED, OK and BUFFER_UNDERFLOW are expected
                    default:
                        throw new IOException("Unexpected status from unwrap: " + result);
                }
                unwrapped += result.bytesConsumed();
                decrypted += result.bytesProduced();

                readBuffer.compact();

                // If we consumed bytes, there is now room in readBuffer for some
                // more.  Even if dsts are full, we may be able to consume more
                // bytes in another call to unwrap().
            } while (result.bytesConsumed() > 0);
        } catch (SSLException ssle) {
            String msg = "Unable to unwrap data using SSLEngine: ";
            msg += ssle.getMessage();
            throw new IOException(msg, ssle);
        }

        return decrypted;
    }

    public int write(ByteBuffer src) throws IOException {
        return (int) write(new ByteBuffer[] { src });
    }

    public synchronized long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        if (outboundClosed) {
            return -1;
        }

        writeBuffer.clear();

        ByteBuffer dst = writeBuffer;

        long wrapped = 0;
        long encrypted = 0;
        long sent = 0;

        try {
            do {
                SSLEngineResult result = engine.wrap(srcs, offset, length, dst);
                if (result.getStatus() != SSLEngineResult.Status.OK && result.getStatus() != SSLEngineResult.Status.CLOSED) {
                    throw new IOException("Unexpected status from wrap: " + result);
                }

                wrapped += result.bytesConsumed();
                encrypted += result.bytesProduced();

                dst.flip();

                int this_write = writeChannel.write(dst);
                sent += this_write;

                if (sent < encrypted && result.bytesConsumed() == 0 && result.bytesProduced() == 0 && this_write == 0) {
                    String msg = "Calls to wrap or write stalled, consuming ";
                    msg += "and producing no data: sent " + sent + " bytes ";
                    msg += "of " + encrypted + " bytes encrypted to peer.";
                    throw new IOException(msg);
                }

                dst.flip();
            } while (sent < encrypted);
        } catch (SSLException ssle) {
            String msg = "Unable to wrap data with SSLEngine: ";
            msg += ssle.getMessage();
            throw new IOException(msg, ssle);
        }

        return sent;
    }

    public void implCloseSelectableChannel() throws IOException {
        // Issue a couple of read and write operations with empty buffers: this
        // should ensure all data gets flushed from the SSLEngine and any
        // alerts (inbound or outbound!) are acknowledged. The minimum sequence
        // should be three: an initial read to see if an inbound alert is
        // present. If one isn't, issuing a write is necessary to send ours
        // out after marking the outbound as closed -- here we need a last read
        // to confirm the peer got the message. Otherwise, only a single write
        // is necessary to send our acknowledgement of the peer's alert.

        try {
            synchronized (this) {
                // unwrap() triggers a call to PR_Read(), which in turn will
                // execute the received alert callback. However, PR_Read is
                // effectively a no-op with an empty buffer, resulting in the
                // callback never triggering. Use a single byte buffer instead,
                // discarding any data because we're closing the channel. This
                // should ensure we always get a callback.
                ByteBuffer read_one = ByteBuffer.allocate(1);

                shutdownInput();

                // Bypass read check.
                inboundClosed = false;
                read(read_one);

                if (!outboundClosed) {
                    shutdownOutput();
                }

                // Make sure we close the input side of the SSLEngine.
                engine.closeInbound();

                outboundClosed = true;
                inboundClosed = true;
            }
        } finally {
            engine.cleanup();
            engine = null;

            if (parent == null) {
                if (autoClose) {
                    parentSocket.shutdownInput();
                    parentSocket.shutdownOutput();
                    parentSocket.close();
                }

                return;
            }

            if (autoClose) {
                parent.shutdownInput();
                parent.shutdownOutput();
                parent.close();
            }
        }
    }

    /* == generic stubs for SocketChannel */

    public JSSSocketChannel bind(SocketAddress local) throws IOException {
        if (parent == null) {
            parentSocket.bind(local);
            return this;
        }

        parent.bind(local);
        return this;
    }

    public boolean connect(SocketAddress remote) throws IOException {
        if (parent == null) {
            parentSocket.connect(remote);
            return true;
        }

        return parent.connect(remote);
    }

    public <T> T getOption(SocketOption<T> name) throws IOException {
        if (parent == null) {
            return null;
        }

        return parent.getOption(name);
    }

    public Set<SocketOption<?>> supportedOptions() {
        if (parent == null) {
            return null;
        }

        return parent.supportedOptions();
    }

    public <T> JSSSocketChannel setOption(SocketOption<T> name, T value) throws IOException {
        if (parent != null) {
            parent.setOption(name, value);
        }

        return this;
    }

    public JSSSocket socket() {
        return sslSocket;
    }

    public boolean isConnected() {
        if (parent == null) {
            return parentSocket.isConnected();
        }

        return parent.isConnected();
    }

    public boolean isConnectionPending() {
        if (parent == null) {
            return !parentSocket.isConnected();
        }

        return parent.isConnectionPending();
    }

    public SocketAddress getLocalAddress() throws IOException {
        if (parent == null) {
            return parentSocket.getLocalSocketAddress();
        }

        return parent.getLocalAddress();
    }

    public SocketAddress getRemoteAddress() throws IOException {
        if (parent == null) {
            return parentSocket.getRemoteSocketAddress();
        }

        return parent.getRemoteAddress();
    }

    public JSSSocketChannel shutdownInput() throws IOException {
        // Hold parent socket/channel open until we've sent CLOSE_NOTIFY
        // messages.
        inboundClosed = true;
        return this;
    }

    public JSSSocketChannel shutdownOutput() throws IOException {
        engine.closeOutbound();
        write(empty);
        outboundClosed = true;

        // Hold parent socket/channel open until we've sent CLOSE_NOTIFY
        // messages.
        return this;
    }

    public void implConfigureBlocking(boolean block) throws IOException {
        if (parent == null) {
            return;
        }

        parent.configureBlocking(block);
    }
}
