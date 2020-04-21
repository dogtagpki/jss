package org.mozilla.jss.ssl.javax;

import java.lang.*;
import java.util.*;

import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.WritableByteChannel;
import java.nio.channels.Channels;

import java.nio.ByteBuffer;

import javax.net.ssl.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mozilla.jss.nss.*;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.provider.javax.crypto.*;
import org.mozilla.jss.ssl.*;

import org.mozilla.jss.crypto.Policy;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.X509Certificate;

/**
 * The reference JSSEngine implementation.
 *
 * This JSSEngine implementation is a reference for future JSSEngine
 * implementations, providing a pure-Java overview of what should happen at
 * each step of the init, wrap, and unwrap calls.
 *
 * This implementation allows for extended debug logging, but also debug
 * packet logging. The latter writes out packets sent via wrap(...) and
 * received from unwrap(...) to a port on localhost. This allows one to easily
 * attach Wireshark or tcpdump and inspect the TLS packets, even if errors
 * occur during the test suite (where packets aren't sent over the wire by
 * default). This maintains the client/server relationship, and are logged
 * as being from the appropriate side of the TLS connection.
 */
public class JSSEngineReferenceImpl extends JSSEngine {
    private String peer_info;

    private boolean closed_fd;
    private BufferProxy read_buf;
    private BufferProxy write_buf;

    private int unknown_state_count;
    private boolean step_handshake;

    private SSLException ssl_exception;
    private boolean seen_exception;

    private int debug_port;
    private ServerSocket ss_socket;
    private Socket s_socket;
    private Socket c_socket;
    private OutputStream s_ostream;
    private OutputStream c_ostream;

    private String name;
    private String prefix = "";

    public JSSEngineReferenceImpl() {
        super();

        peer_info = "";

        debug("JSSEngine: constructor()");
    }

    public JSSEngineReferenceImpl(String peerHost, int peerPort) {
        super(peerHost, peerPort);

        peer_info = peerHost + ":" + peerPort;

        debug("JSSEngine: constructor(" + peerHost + ", " + peerPort + ")");
    }

    public JSSEngineReferenceImpl(String peerHost, int peerPort,
                     org.mozilla.jss.crypto.X509Certificate localCert,
                     org.mozilla.jss.crypto.PrivateKey localKey) {
        super(peerHost, peerPort, localCert, localKey);

        peer_info = peerHost + ":" + peerPort;
        prefix = prefix + "[" + peer_info + "] ";

        debug("JSSEngine: constructor(" + peerHost + ", " + peerPort + ", " + localCert + ", " + localKey + ")");
    }

    private String errorText(int error) {
        // Convert the given error into a pretty string representation with
        // as much information as is currently available.

        String error_name = PR.ErrorToName(error);
        String error_text = PR.GetErrorText();

        if (error == 0) {
            return "NO ERROR";
        } else if (error_name.isEmpty()) {
            return "UNKNOWN (" + error + ")";
        } else if (error_text.isEmpty()) {
            return error_name + " (" + error + ")";
        } else {
            return error_name + " (" + error + "): " + error_text;
        }
    }

    private void debug(String msg) {
        logger.debug(prefix + msg);
    }

    private void info(String msg) {
        logger.info(prefix + msg);
    }

    private void warn(String msg) {
        logger.warn(prefix + msg);
    }

    public void setName(String name) {
        this.name = name;
        prefix = "[" + this.name + "] " + prefix;
    }

    private void init() {
        debug("JSSEngine: init()");

        // Initialize our JSSEngine when we begin to handshake; otherwise,
        // calls to Set<Option>(...) won't be processed if we call it too
        // early; some of these need to be applied at initialization.

        // Ensure we don't leak ssl_fd if we're called multiple times.
        if (ssl_fd != null && !closed_fd) {
            is_inbound_closed = true;
            is_outbound_closed = true;
            cleanup();
        }

        ssl_fd = null;

        // Create buffers for interacting with NSS.
        createBuffers();
        createBufferFD();

        // Initialize the appropriate end of this connection.
        if (as_server) {
            initServer();
        } else {
            initClient();
        }

        // Apply the requested cipher suites and protocols.
        applyProtocols();
        applyCiphers();

        // Apply hostname information (via setURL).
        applyHosts();

        // Apply TrustManager(s) information for validating the peer's
        // certificate.
        applyTrustManagers();

        // Finally, set up any debug logging necessary.
        createLoggingSocket();
    }

    private void createBuffers() {
        debug("JSSEngine: createBuffers()");

        // If the buffers exist, destroy them and recreate.
        if (read_buf != null) {
            Buffer.Free(read_buf);
        }
        read_buf = Buffer.Create(BUFFER_SIZE);

        if (write_buf != null) {
            Buffer.Free(write_buf);
        }
        write_buf = Buffer.Create(BUFFER_SIZE);
    }

    private void createBufferFD() {
        debug("JSSEngine: createBufferFD()");

        // Create the basis for the ssl_fd from the pair of buffers.
        PRFDProxy fd;
        if (peer_info != null && peer_info.length() != 0) {
            fd = PR.NewBufferPRFD(read_buf, write_buf, peer_info.getBytes());
        } else {
            fd = PR.NewBufferPRFD(read_buf, write_buf, null);
        }

        if (fd == null) {
            throw new RuntimeException("JSSEngine.init(): Error creating buffer-backed PRFileDesc.");
        }

        // Initialize ssl_fd from the model Buffer-backed PRFileDesc.
        ssl_fd = SSL.ImportFD(null, fd);
        closed_fd = false;

        // Turn on SSL Alert Logging for the ssl_fd object.
        int ret = SSL.EnableAlertLogging(ssl_fd);
        if (ret == SSL.SECFailure) {
            throw new RuntimeException("JSSEngine.init(): Unable to enable SSL Alert Logging on this SSLFDProxy instance.");
        }

        // Pass this ssl_fd to the session object so that we can use
        // SSL methods to invalidate the session.
    }

    private void initClient() {
        debug("JSSEngine: initClient()");

        // Update handshake status; client initiates connection, so we
        // need to wrap first.
        handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;

        if (cert != null && key != null) {
            debug("JSSEngine.initClient(): Enabling client auth: " + cert);
            ssl_fd.SetClientCert(cert);
            if (SSL.AttachClientCertCallback(ssl_fd) != SSL.SECSuccess) {
                throw new RuntimeException("JSSEngine.init(): Unable to attach client certificate auth callback.");
            }
        }

        step_handshake = true;
    }

    private void initServer() {
        debug("JSSEngine: initServer()");

        // The only time cert and key are required are when we're creating a
        // server SSLEngine.
        if (cert == null || key == null) {
            throw new IllegalArgumentException("JSSEngine: must be initialized with server certificate and key!");
        }

        debug("JSSEngine.initServer(): " + cert);
        debug("JSSEngine.initServer(): " + key);

        // Configure SSL server with the given certificate and its private
        // key.
        if (SSL.ConfigServerCert(ssl_fd, cert, key) == SSL.SECFailure) {
            throw new RuntimeException("Unable to initialize server with cert and key: " + errorText(PR.GetError()));
        }
        session.setLocalCertificates(new PK11Cert[]{ cert } );

        // Create a small session cache.
        //
        // TODO: Make this configurable.
        if (SSL.ConfigServerSessionIDCache(1, 100, 100, null) == SSL.SECFailure) {
            throw new RuntimeException("Unable to configure server session cache: " + errorText(PR.GetError()));
        }

        // Update handshake status; client initiates connection, so wait
        // for unwrap on the server end.
        handshake_state = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;

        // Only specify these on the server side as they affect what we
        // want from the remote peer in NSS. In the server case, this is
        // client auth, but if we were to set these on the client, it would
        // affect server auth.
        if (SSL.OptionSet(ssl_fd, SSL.REQUEST_CERTIFICATE, want_client_auth || need_client_auth ? 1 : 0) == SSL.SECFailure) {
            throw new RuntimeException("Unable to configure SSL_REQUEST_CERTIFICATE option: " + errorText(PR.GetError()));
        }

        if (SSL.OptionSet(ssl_fd, SSL.REQUIRE_CERTIFICATE, need_client_auth ? 1 : 0) == SSL.SECFailure) {
            throw new RuntimeException("Unable to configure SSL_REQUIRE_CERTIFICATE option: " + errorText(PR.GetError()));
        }

        step_handshake = true;
    }

    private void applyCiphers() {
        debug("JSSEngine: applyCiphers()");
        // Enabled the ciphersuites specified by setEnabledCipherSuites(...).
        // When this isn't called, enabled_ciphers will be null, so we'll just
        // use whatever is enabled by default.
        if (enabled_ciphers == null) {
            return;
        }

        // We need to disable the suite if it isn't present in the list of
        // suites above. Be lazy about it for the time being and disable all
        // cipher suites first.
        for (SSLCipher suite : SSLCipher.values()) {
            if (SSL.CipherPrefSet(ssl_fd, suite.getID(), false) == SSL.SECFailure) {
                // warn("Unable to set cipher suite preference for " + suite.name() + ": " + errorText(PR.GetError()));
            }
        }

        // Only enable these particular suites. When a cipher suite can't be
        // enabled it is most likely due to local policy. Log it. Also log
        // which ciphers were successfully enabled for debugging purposes.
        for (SSLCipher suite : enabled_ciphers) {
            if (suite == null) {
                continue;
            }

            if (SSL.CipherPrefSet(ssl_fd, suite.getID(), true) == SSL.SECFailure) {
                warn("Unable to enable cipher suite " + suite + ": " + errorText(PR.GetError()));
            } else {
                debug("Enabled cipher suite " + suite + ": " + errorText(PR.GetError()));
            }
        }
    }

    private void applyProtocols() {
        debug("JSSEngine: applyProtocols() min_protocol=" + min_protocol + " max_protocol=" + max_protocol);
        // Enable the protocols only when both a maximum and minimum protocol
        // version are specified.
        if (min_protocol == null || max_protocol == null) {
            debug("JSSEngine: applyProtocols() - missing min_protocol or max_protocol; using defaults");
            return;
        }

        // We should bound this range by crypto-policies in the future to
        // match the current behavior.
        SSLVersionRange vrange = new SSLVersionRange(min_protocol, max_protocol);
        if (SSL.VersionRangeSet(ssl_fd, vrange) == SSL.SECFailure) {
            throw new RuntimeException("Unable to set version range: " + errorText(PR.GetError()));
        }
    }

    private void applyHosts() {
        debug("JSSEngine: applyHosts()");

        // This is most useful for the client end of the connection; this
        // specifies what to match the server's certificate against.
        if (hostname != null) {
            if (SSL.SetURL(ssl_fd, hostname) == SSL.SECFailure) {
                throw new RuntimeException("Unable to configure server hostname: " + errorText(PR.GetError()));
            }
        }
    }

    private void applyTrustManagers() {
        debug("JSSEngine: applyTrustManagers()");

        // If none have been specified, exit early.
        if (trust_managers == null || trust_managers.length == 0) {
            debug("JSSEngine: no TrustManagers to apply.");
            return;
        }

        // Check if we have a single JSSNativeTrustManager.
        if (trust_managers.length == 1 && trust_managers[0] instanceof JSSNativeTrustManager) {
            // This is a dummy TrustManager. It signifies that we should call
            // SSL.ConfigJSSDefaultCertAuthCallback(...) on this SSL
            // PRFileDesc pointer, letting us utilize the same certificate
            // validation logic that SSLSocket had.
            debug("JSSEngine: applyTrustManagers() - adding Native TrustManager");
            if (SSL.ConfigJSSDefaultCertAuthCallback(ssl_fd) == SSL.SECFailure) {
                throw new RuntimeException("Unable to configure JSSNativeTrustManager on this JSSengine: " + errorText(PR.GetError()));
            }
        }
    }

    private void createLoggingSocket() {
        if (debug_port == 0) {
            return;
        }

        try {
            ss_socket = new ServerSocket(debug_port);
            ss_socket.setReuseAddress(true);
            ss_socket.setReceiveBufferSize(BUFFER_SIZE);

            c_socket = new Socket(ss_socket.getInetAddress(), ss_socket.getLocalPort());
            c_socket.setReuseAddress(true);
            c_socket.setReceiveBufferSize(BUFFER_SIZE);
            c_socket.setSendBufferSize(BUFFER_SIZE);

            s_socket = ss_socket.accept();
            s_socket.setReuseAddress(true);
            s_socket.setReceiveBufferSize(BUFFER_SIZE);
            s_socket.setSendBufferSize(BUFFER_SIZE);

            s_ostream = s_socket.getOutputStream();

            c_ostream = c_socket.getOutputStream();
        } catch (Exception e) {
            throw new RuntimeException("Unable to enable debug socket logging! " + e.getMessage(), e);
        }
    }

    public void beginHandshake() {
        debug("JSSEngine: beginHandshake()");

        // We assume beginHandshake(...) is the entry point for initializing
        // the buffer. In particular, wrap(...) / unwrap(...) *MUST* call
        // beginHandshake(...) if ssl_fd == null.

        // ssl_fd == null <-> we've not initialized anything yet.
        if (ssl_fd == null) {
            init();
        }

        // Always, reset the handshake status, using the existing
        // socket and configuration (which might've been just created).
        if (SSL.ResetHandshake(ssl_fd, as_server) == SSL.SECFailure) {
            throw new RuntimeException("Unable to begin handshake: " + errorText(PR.GetError()));
        }
    }

    public void closeInbound() {
        debug("JSSEngine: closeInbound()");

        PR.Shutdown(ssl_fd, PR.SHUTDOWN_RCV);
        is_inbound_closed = true;
    }

    public void closeOutbound() {
        debug("JSSEngine: closeOutbound()");

        PR.Shutdown(ssl_fd, PR.SHUTDOWN_SEND);
        is_outbound_closed = true;
    }

    public String getHostname() {
        return hostname;
    }

    public Runnable getDelegatedTask() {
        debug("JSSEngine: getDelegatedTask()");

        // We fake being a non-blocking SSLEngine. In particular, we never
        // export tasks as delegated tasks (e.g., OCSP checking), so this
        // method will always return null.

        return null;
    }

    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        debug("JSSEngine: getHandshakeStatus()");

        // Always update the handshake state; this ensures that we catch
        // looping due to missing data and flip our expected direction.
        updateHandshakeState();

        return handshake_state;
    }

    public SecurityStatusResult getStatus() {
        if (ssl_fd == null) {
            return null;
        }

        return SSL.SecurityStatus(ssl_fd);
    }

    /**
     * Enable writing of encrypted TLS traffic to the specified port in a
     * client-server relationship (mirroring the actual role of this
     * SSLEngine) to enable debugging with Wireshark.
     */
    public void enableSafeDebugLogging(int port) {
        debug_port = port;
    }

    private int computeSize(ByteBuffer[] buffers, int offset, int length) throws IllegalArgumentException {
        debug("JSSEngine: computeSize()");
        int result = 0;

        if (buffers == null || buffers.length == 0) {
            debug("JSSEngine.compueSize(): no buffers - result=" + result);
            return result;
        }

        // Semantics of arguments:
        //
        // - buffers is where we're reading/writing application data.
        // - offset is the index of the first buffer we read/write to.
        // - length is the total number of buffers we read/write to.
        //
        // We use a relative index and an absolute index to handle these
        // constraints.
        for (int rel_index = 0; rel_index < length; rel_index++) {
            int index = offset + rel_index;
            if (index >= buffers.length) {
                throw new IllegalArgumentException("offset (" + offset + ") or length (" + length + ") exceeds contract based on number of buffers (" + buffers.length + ")");
            }

            if (rel_index == 0 && buffers[index] == null) {
                // If our first buffer is null, assume the rest are and skip
                // everything else. This commonly happens when null is passed
                // as the src parameter to wrap or when null is passed as the
                // dst parameter to unwrap.
                debug("JSSEngine.compueSize(): null first buffer - result=" + result);
                return result;
            }

            if (buffers[index] == null) {
                throw new IllegalArgumentException("Buffer at index " + index + " is null.");
            }

            result += buffers[index].remaining();
        }

        debug("JSSEngine.compueSize(): result=" + result);

        return result;
    }

    private int putData(byte[] data, ByteBuffer[] buffers, int offset, int length) {
        debug("JSSEngine: putData()");
        // Handle the rather unreasonable task of moving data into the buffers.
        // We assume the buffer parameters have already been checked by
        // computeSize(...); that is, offset/length contracts hold and that
        // each buffer in the range is non-null.
        //
        // We also assume that data.length does not exceed the total number
        // of bytes the buffers can hold; this is what computeSize(...)'s
        // return value should ensure. This directly means that the inner
        // while loop won't exceed the bounds of offset+length.

        int buffer_index = offset;
        int data_index = 0;

        if (data == null || buffers == null) {
            return data_index;
        }

        for (data_index = 0; data_index < data.length; data_index++) {
            // Ensure we have have a buffer with capacity.
            while ((buffers[buffer_index] == null || buffers[buffer_index].remaining() <= 0) &&
                    (buffer_index < offset + length)) {
                buffer_index += 1;
            }
            if (buffer_index >= offset + length) {
                break;
            }

            // TODO: use bulk copy
            buffers[buffer_index].put(data[data_index]);
        }

        return data_index;
    }

    private void updateSession() {
        if (ssl_fd == null) {
            return;
        }

        try {
            PK11Cert[] peer_chain = SSL.PeerCertificateChain(ssl_fd);
            session.setPeerCertificates(peer_chain);

            SSLChannelInfo info = SSL.GetChannelInfo(ssl_fd);
            if (info == null) {
                return;
            }

            session.setId(info.getSessionID());
            session.refreshData();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private SSLException checkSSLAlerts() {
        debug("JSSEngine: Checking inbound and outbound SSL Alerts. Have " + ssl_fd.inboundAlerts.size() + " inbound and " + ssl_fd.outboundAlerts.size() + " outbound alerts.");

        // Prefer inbound alerts to outbound alerts.
        while (ssl_fd.inboundOffset < ssl_fd.inboundAlerts.size()) {
            SSLAlertEvent event = ssl_fd.inboundAlerts.get(ssl_fd.inboundOffset);
            ssl_fd.inboundOffset += 1;

            if (event.getLevelEnum() == SSLAlertLevel.WARNING && event.getDescriptionEnum() == SSLAlertDescription.CLOSE_NOTIFY) {
                warn("Got inbound CLOSE_NOTIFY alert");
                closeInbound();
            }

            debug("JSSEngine: Got inbound alert: " + event);

            SSLException exception = event.toException();
            if (exception != null) {
                return exception;
            }
        }

        while (ssl_fd.outboundOffset < ssl_fd.outboundAlerts.size()) {
            SSLAlertEvent event = ssl_fd.outboundAlerts.get(ssl_fd.outboundOffset);
            ssl_fd.outboundOffset += 1;

            if (event.getLevelEnum() == SSLAlertLevel.WARNING && event.getDescriptionEnum() == SSLAlertDescription.CLOSE_NOTIFY) {
                warn("Sent outbound CLOSE_NOTIFY alert.");
                closeOutbound();
            }

            debug("JSSEngine: Got outbound alert: " + event);

            SSLException exception = event.toException();
            if (exception != null) {
                return exception;
            }
        }

        return null;
    }

    private void updateHandshakeState() {
        debug("JSSEngine: updateHandshakeState()");

        // If we've previously seen an exception, we should just return
        // here; there's already an alert on the wire, so there's no point
        // in checking for new ones and/or stepping the handshake: it has
        // already failed.
        if (seen_exception) {
            return;
        }

        // Before we step the handshake, check our current security status.
        // This informs us of our possible return codes. Also, if we're
        // currently on, update our handshake status. This happens even if
        // we later exit before calling SSL.ForceHandshake() so that we can
        // see what the session data contains.
        SecurityStatusResult preHandshakeStatus = getStatus();
        if (preHandshakeStatus.on >= 1) {
            updateSession();
        }


        // If we're already done, we should check for SSL ALerts.
        if (!step_handshake && handshake_state == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            debug("JSSEngine.updateHandshakeState() - not handshaking");
            unknown_state_count = 0;

            ssl_exception = checkSSLAlerts();
            seen_exception = (ssl_exception != null);
            return;
        }

        // If we've previously finished handshaking, then move to
        // NOT_HANDSHAKING. Now is also a good time to check for any
        // alerts.
        if (!step_handshake && handshake_state == SSLEngineResult.HandshakeStatus.FINISHED) {
            debug("JSSEngine.updateHandshakeState() - FINISHED to NOT_HANDSHAKING");
            handshake_state = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
            unknown_state_count = 0;

            ssl_exception = checkSSLAlerts();
            seen_exception = (ssl_exception != null);
            return;
        }

        // Since we're not obviously done handshaking, and the last time we
        // were called, we were still handshaking, step the handshake.
        debug("JSSEngine.updateHandshakeState() - forcing handshake");
        if (SSL.ForceHandshake(ssl_fd) == SSL.SECFailure) {
            int error_value = PR.GetError();

            if (error_value != PRErrors.WOULD_BLOCK_ERROR) {
                debug("JSSEngine.updateHandshakeState() - FATAL " + getStatus());

                ssl_exception = new SSLHandshakeException("Error duing SSL.ForceHandshake() :: " + errorText(error_value));
                seen_exception = true;

                handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                return;
            }
        }

        // Check if we've just finished handshaking.
        SecurityStatusResult handshakeStatus = getStatus();
        debug("JSSSEngine.updateHandshakeState() - pre: " + preHandshakeStatus);
        debug("JSSSEngine.updateHandshakeState() - post: " + handshakeStatus);
        debug("JSSEngine.updateHandshakeState() - read_buf.read=" + Buffer.ReadCapacity(read_buf) + " read_buf.write=" + Buffer.WriteCapacity(read_buf) + " write_buf.read=" + Buffer.ReadCapacity(write_buf) + " write_buf.write=" + Buffer.WriteCapacity(write_buf));

        // Set NEED_WRAP when we have data to send to the client.
        if (Buffer.ReadCapacity(write_buf) > 0 && handshake_state != SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            // Can't write; to read, we need to call wrap to provide more
            // data to write.
            debug("JSSEngine.updateHandshakeState() - can write " + Buffer.ReadCapacity(write_buf) + " bytes, NEED_WRAP to process");
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;
            unknown_state_count = 0;
            return;
        }

        // Delay the check to see if the handshake finished until after we
        // send the CLIENT FINISHED message and recieved the SERVER FINISHED
        // message if we're a client. Otherwise, wait to send SERVER FINISHED
        // message. This is because NSS thinks the handshake has finished
        // (according to SecurityStatusResult since it has sent the massage)
        // but we haven't yet gotten around to doing so if we're in a WRAP()
        // call.
        if (handshakeStatus.on >= 1 && Buffer.ReadCapacity(write_buf) == 0) {
            debug("JSSEngine.updateHandshakeState() - handshakeStatus.on is " + handshakeStatus.on + ", so we've just finished handshaking");
            step_handshake = false;
            handshake_state = SSLEngineResult.HandshakeStatus.FINISHED;
            unknown_state_count = 0;
            return;
        }

        if (Buffer.ReadCapacity(read_buf) == 0 && handshake_state != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
            // Set NEED_UNWRAP when we have no data to read from the client.
            debug("JSSEngine.updateHandshakeState() - can read " + Buffer.ReadCapacity(read_buf) + " bytes, NEED_UNWRAP to give us more");
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
            unknown_state_count = 0;
            return;
        }

        unknown_state_count += 1;
        if (unknown_state_count >= 4) {
            if (handshake_state == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                handshake_state = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
            } else {
                handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;
            }
            unknown_state_count = 1;
        }
    }

    private boolean isHandshakeFinished() {
        debug("JSSEngine: isHandshakeFinished()");
        return (handshake_state == SSLEngineResult.HandshakeStatus.FINISHED ||
                (ssl_fd != null && handshake_state == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING));
    }

    private void logUnwrap(ByteBuffer src) {
        if (debug_port <= 0 || src == null || src.remaining() == 0) {
            return;
        }

        OutputStream stream = c_ostream;

        if (!as_server) {
            // An unwrap from the client means we write data to the outbound
            // side of the server socket.
            stream = s_ostream;
        }

        WritableByteChannel channel = Channels.newChannel(stream);

        int pos = src.position();
        try {
            debug("JSSEngine: logUnwrap() - writing " + src.remaining() + " bytes.");
            channel.write(src);
            stream.flush();
        } catch (Exception e) {
            throw new RuntimeException("Unable to log contents of unwrap's src to debug socket: " + e.getMessage(), e);
        } finally {
            src.position(pos);
        }
    }

    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws IllegalArgumentException, SSLException {
        debug("JSSEngine: unwrap(ssl_fd=" + ssl_fd + ")");

        // In this method, we're taking the network wire contents of src and
        // passing them as the read side of our buffer. If there's any data
        // for us to read from the remote peer (via ssl_fd), we place it in
        // the various dsts.
        //
        // However, we also need to detect if the handshake is still ongoing;
        // if so, we can't send data (from src) until then.

        if (ssl_fd == null) {
            beginHandshake();
        }

        logUnwrap(src);

        // wire_data is the number of bytes from src we've written into
        // read_buf. This is bounded above by src.capcity but also the
        // free space left in read_buf to write to. Allows us to size the
        // temporary byte array appropriately.
        int wire_data = (int) Buffer.WriteCapacity(read_buf);
        if (src == null) {
            wire_data = 0;
        } else {
            // We need to know how many bytes have been written into src: this
            // is via src.remaining().
            wire_data = Math.min(wire_data, src.remaining());
        }

        // Order of operations:
        //  1. Read data from srcs
        //  2. Update handshake status
        //  3. Write data to dsts
        //
        // Since srcs is coming from the data, it could affect our ability to
        // handshake. It could also affect our ability to write data to dsts,
        // as src could provide new data to decrypt. When no new data from src
        // is present, we could have residual steps in handshake(), in which
        // case no data would be written to dsts. Lastly, even if no new data
        // from srcs, could still have residual data in read_buf, so we should
        // attempt to read from the ssl_fd.

        // When we have data from src, write it to read_buf.
        if (wire_data > 0) {
            byte[] wire_buffer = new byte[wire_data];
            src.get(wire_buffer);
            int written = (int) Buffer.Write(read_buf, wire_buffer);

            // For safety: ensure everything we thought we could write was
            // actually written. Otherwise, we've done something wrong.
            wire_data = Math.min(wire_data, written);

            // TODO: Determine if we should write the trail of wire_buffer
            // back to the front of src... Seems like unnecessary work.
            debug("JSSEngine.unwrap(): Wrote " + wire_data + " bytes to read_buf.");
        }

        // In the above, we should always try to read and write data. Check to
        // see if we need to step our handshake process or not.
        updateHandshakeState();

        // Actual amount of data written to the buffer.
        int app_data = 0;

        // Maximum theoretical amount of data we could've written to the
        // destination. This is bounded by the lower of both the size of
        // our dsts and the maximum BUFFER_SIZE. Worst case, we'll be forced
        // to call unwrap(...) multiple times.
        int max_app_data = Math.min(computeSize(dsts, offset, length), BUFFER_SIZE);

        // When we have app data to write over the network, go ahead and do
        // so. This involves reading from ssl_fd and writing to dsts. We don't
        // currently have a good proxy metric for "can read from a ssl_fd",
        // so always attempt it. In particular, even if the handshake isn't
        // finished, we still need to call PR.Read(...) or PR.Write(...) in
        // order to tell if an inbound alert was received.
        if (max_app_data > 0) {
            byte[] app_buffer = PR.Read(ssl_fd, max_app_data);
            debug("JSSEngine.unwrap() - " + app_buffer + " error=" + errorText(PR.GetError()));
            if (app_buffer != null) {
                app_data = putData(app_buffer, dsts, offset, length);
            } else {
                int error = PR.GetError();
                if (error != 0 && error != PRErrors.WOULD_BLOCK_ERROR) {
                    ssl_exception = new SSLException("Unexpected return from PR.Read(): " + errorText(error));
                    seen_exception = true;
                }
            }

            if (seen_exception == false && ssl_exception == null) {
                ssl_exception = checkSSLAlerts();
                seen_exception = (ssl_exception != null);
            }
        }

        // Before we return, check if an exception occurred and throw it if
        // one did.
        if (ssl_exception != null) {
            info("JSSEngine.unwrap() - Got SSLException: " + ssl_exception);
            SSLException excpt = ssl_exception;
            ssl_exception = null;
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;
            tryCleanup();
            throw excpt;
        }

        SSLEngineResult.Status handshake_status = SSLEngineResult.Status.OK;


        if (is_inbound_closed && is_outbound_closed) {
            debug("Socket is currently closed.");
            handshake_status = SSLEngineResult.Status.CLOSED;
        }

        // Need a way to introspect the open/closed state of the TLS
        // connection.

        debug("JSSEngine.unwrap() - Finished");
        debug(" - Status: " + handshake_status);
        debug(" - Handshake State: " + handshake_state);
        debug(" - wire_data: " + wire_data);
        debug(" - app_data: " + app_data);

        tryCleanup();
        return new SSLEngineResult(handshake_status, handshake_state, wire_data, app_data);
    }

    public int writeData(ByteBuffer[] srcs, int offset, int length) {
        debug("JSSEngine: writeData()");
        // This is the tough end of reading/writing. There's two potential
        // places buffering could occur:
        //
        //  - Inside the NSS library (unclear if this happens).
        //  - write_buf
        //
        // So when we call PR.Write(ssl_fd, data), it isn't guaranteed that
        // we can write all of data to ssl_fd (unlike with all our other read
        // or write operations where we have a clear bound). In the event that
        // our Write call is truncated, we have to put data back into the
        // buffer from whence it was read.
        //
        // However, we do use Buffer.WriteCapacity(write_buf) as a proxy
        // metric for how much we can write without having to place data back
        // in a src buffer.
        int data_length = 0;

        int index = offset;
        int max_index = offset + length;

        while (index < max_index) {
            // If we don't have any remaining bytes in this buffer, skip it.
            if (srcs[index].remaining() <= 0) {
                index += 1;
                continue;
            }
            debug("JSSEngine.writeData(): index=" + index + " max_index=" + max_index);

            // We expect (i.e., need to construct a buffer) to write up to
            // this much. Note that this is non-zero since we're taking the
            // max here and we guarantee with the previous statement that
            // srcs[index].remaining() > 0.
            int expected_write = srcs[index].remaining();
            debug("JSSEngine.writeData(): expected_write=" + expected_write + " write_cap=" + Buffer.WriteCapacity(write_buf) + " read_cap=" + Buffer.ReadCapacity(read_buf));

            // Get data from our current srcs[index] buffer.
            byte[] app_data = new byte[expected_write];
            srcs[index].get(app_data);

            // Actual amount written.
            int this_write = PR.Write(ssl_fd, app_data);
            debug("JSSEngine.writeData(): this_write=" + this_write);
            if (this_write < 0) {
                int error = PR.GetError();
                if (error == PRErrors.SOCKET_SHUTDOWN_ERROR) {
                    warn("NSPR reports outbound socket is shutdown.");
                    is_outbound_closed = true;
                } else if (error != PRErrors.WOULD_BLOCK_ERROR) {
                    throw new RuntimeException("Unable to write to internal ssl_fd: " + errorText(PR.GetError()));
                }

                break;
            }

            data_length += this_write;

            if (this_write == 0) {
                // Revert our position to the previous position and break: we
                // are out of space to write into our SSL FD.
                int pos = srcs[index].position();
                int delta = expected_write - this_write;
                srcs[index].position(pos - delta);

                // Also check for SSLExceptions while we're here.
                break;
            }
        }

        debug("JSSEngine.writeData(): data_length=" + data_length);

        return data_length;
    }

    private void logWrap(ByteBuffer dst) {
        if (debug_port <= 0 || dst == null || dst.remaining() == 0) {
            return;
        }

        OutputStream stream = s_ostream;

        if (!as_server) {
            // A wrap from the client means we write data to the outbound
            // side of the client socket.
            stream = c_ostream;
        }

        WritableByteChannel channel = Channels.newChannel(stream);

        int pos = dst.position();
        try {
            dst.flip();
            debug("JSSEngine: logWrap() - writing " + dst.remaining() + " bytes.");
            channel.write(dst);
            stream.flush();
            dst.flip();
        } catch (Exception e) {
            throw new RuntimeException("Unable to log contents of wrap's dst to debug socket: " + e.getMessage(), e);
        } finally {
            dst.position(pos);
        }
    }

    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws IllegalArgumentException, SSLException {
        debug("JSSEngine: wrap(ssl_fd=" + ssl_fd + ")");
        // In this method, we're taking the application data from the various
        // srcs and writing it to the remote peer (via ssl_fd). If there's any
        // data for us to send to the remote peer, we place it in dst.
        //
        // However, we also need to detect if the handshake is still ongoing;
        // if so, we can't send data (from src) until then.

        if (ssl_fd == null) {
            beginHandshake();
        }

        // Order of operations:
        //  1. Step the handshake
        //  2. Write data from srcs to ssl_fd
        //  3. Write data from write_buf to dst
        //
        // This isn't technically locally optimal: it could be that write_buf
        // is full while we're handshaking so step 1 could be a no-op, but
        // we could read from write_buf and step the handshake then. However,
        // on our next call to wrap() would also step the handshake, which
        // two in a row would almost certainly result in one being a no-op.
        // Both steps 1 and 2 could write data to dsts. At best 2 will fail if
        // write_buf is full, however, we'd again end up calling wrap() again
        // anyways.

        // In the above order of operations, we should always try to read and
        // write data. Check to see if we need to step our handshake process
        // or not.
        updateHandshakeState();

        if (ssl_exception == null && seen_exception) {
            if (handshake_state != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                // In the event that:
                //
                //      1. We saw an exception in the past
                //          --> (seen_exception is true),
                //      2. We've already thrown it from wrap or unwrap,
                //          --> (ssl_exception is null),
                //      3. We were previously handshaking
                //          --> (handshake_state is a handshaking state),
                //
                // we need to make sure wrap is called again to ensure the
                // alert is actually written to the wire. So here we are,
                // in wrap and the above hold true; we can mark the handshake
                // status as "FINISHED" (because well, it is over due to the
                // alert). That leaves the return state to be anything other
                // than OK to indicate the error.
                handshake_state = SSLEngineResult.HandshakeStatus.FINISHED;
            }
        }

        // Actual amount of data read from srcs (and written to ssl_fd). This
        // is determined by the PR.Write(...) call on ssl_fd.
        int app_data = 0;

        // Maximum theoretical amount of data we could've read from srcs.
        // While this isn't strictly bounded above by BUFFER_SIZE (as it is
        // being written to ssl_fd instead of to read_buf or write_buf), we're
        // better off limiting ourselves to a reasonable limit.
        int max_app_data = Math.min(computeSize(srcs, offset, length), BUFFER_SIZE);

        // Try writing data from srcs to the other end of the connection. Note
        // that we always attempt this, even if the handshake isn't yet marked
        // as finished. This is because we need the call to PR.Write(...) to
        // tell if an alert is getting sent.
        if (max_app_data > 0) {
            debug("JSSEngine.wrap(): writing from srcs to buffer...");
            app_data = writeData(srcs, offset, length);

            if (seen_exception == false && ssl_exception == null) {
                ssl_exception = checkSSLAlerts();
                seen_exception = (ssl_exception != null);
            }
        } else {
            debug("JSSEngine.wrap(): not writing from srcs to buffer: max_app_data=" + max_app_data + " handshake_finished=" + isHandshakeFinished());
        }

        // wire_data is the number of bytes written to dst. This is bounded
        // above by two fields: the number of bytes we can read from
        // write_buf, and the size of dst, if present.
        int wire_data = (int) Buffer.ReadCapacity(write_buf);
        if (dst == null) {
            wire_data = 0;
        } else {
            // We want to know how much free space there is in dst for us to
            // write to. This is given by dst.remaining().
            wire_data = Math.min(wire_data, dst.remaining());
        }

        // Try reading data from write_buf to dst
        if (wire_data > 0) {
            byte[] wire_buffer = Buffer.Read(write_buf, wire_data);
            dst.put(wire_buffer);
            debug("JSSEngine.wrap() - Wrote " + wire_buffer.length + " bytes to dst.");
        }

        logWrap(dst);

        // Before we return, check if an exception occurred and throw it if
        // one did.
        if (ssl_exception != null) {
            info("JSSEngine.wrap() - Got SSLException: " + ssl_exception);
            SSLException excpt = ssl_exception;
            ssl_exception = null;
            cleanup();
            throw excpt;
        }

        // Need a way to introspect the open/closed state of the TLS
        // connection.

        SSLEngineResult.Status handshake_status = SSLEngineResult.Status.OK;

        if (ssl_exception == null && seen_exception) {
            debug("Seen and processed exception; closing inbound and outbound because this was the last wrap(...)");
            closeInbound();
            closeOutbound();
        }

        if (is_inbound_closed && is_outbound_closed) {
            debug("Socket is currently closed.");
            handshake_status = SSLEngineResult.Status.CLOSED;
        }

        debug("JSSEngine.wrap() - Finished");
        debug(" - Status: " + handshake_status);
        debug(" - Handshake State: " + handshake_state);
        debug(" - wire_data: " + wire_data);
        debug(" - app_data: " + app_data);

        tryCleanup();
        return new SSLEngineResult(handshake_status, handshake_state, app_data, wire_data);
    }

    /**
     * Calls cleanup only if both inbound and outbound data streams are
     * closed.
     *
     * This prevents accidental cleanup in the case of a partially open
     * connection.
     */
    public void tryCleanup() {
        debug("JSSEngine: tryCleanup()");
        if (is_inbound_closed && is_outbound_closed) {
            // throw new RuntimeException("Probably shouldn't be here!");
            cleanup();
        }
    }

    /**
     * Performs cleanup of internal data, closing both inbound and outbound
     * data streams if still open.
     */
    public void cleanup() {
        debug("JSSEngine: cleanup()");

        if (!is_inbound_closed) {
            debug("JSSEngine: cleanup() - closing opened inbound socket");
            closeInbound();
        }

        if (!is_outbound_closed) {
            debug("JSSEngine: cleanup() - closing opened outbound socket");
            closeOutbound();
        }

        // First cleanup any debugging ports, if any.
        cleanupLoggingSocket();

        // Then clean up the NSS state.
        cleanupSSLFD();
    }

    private void cleanupLoggingSocket() {
        if (debug_port > 0) {
            try {
                s_socket.close();
            } catch (Exception e) {}

            try {
                c_socket.close();
            } catch (Exception e) {}

            try {
                ss_socket.close();
            } catch (Exception e) {}
        }
    }

    private void cleanupSSLFD() {
        if (!closed_fd) {
            try {
                SSL.RemoveCallbacks(ssl_fd);
                PR.Close(ssl_fd);
                ssl_fd.close();
            } catch (Exception e) {
            } finally {
                closed_fd = true;
            }
        }

        Buffer.Free(read_buf);
        Buffer.Free(write_buf);
    }
}
