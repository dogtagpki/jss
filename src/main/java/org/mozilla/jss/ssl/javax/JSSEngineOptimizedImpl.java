package org.mozilla.jss.ssl.javax;

import java.lang.*;
import java.util.*;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.WritableByteChannel;
import java.nio.channels.Channels;
import java.security.PublicKey;
import java.security.cert.CertificateException;

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
 * An optimized JSSEngine implementation.
 *
 * This JSSEngine implementation is optimized for lower JNI overhead when
 * compared to the reference implementation.
 */
public class JSSEngineOptimizedImpl extends JSSEngine {
    private String peer_info;

    private boolean closed_fd = true;
    private ByteBufferProxy read_buf;
    private ByteBufferProxy write_buf;

    private int unknown_state_count;
    private boolean step_handshake;

    private SSLException ssl_exception;
    private boolean seen_exception;

    private CertValidationTask task;

    public JSSEngineOptimizedImpl() {
        super();

        peer_info = "";

        logger.debug("JSSEngine: constructor()");
    }

    public JSSEngineOptimizedImpl(String peerHost, int peerPort) {
        super(peerHost, peerPort);

        peer_info = peerHost + ":" + peerPort;

        logger.debug("JSSEngine: constructor(" + peerHost + ", " + peerPort + ")");
    }

    public JSSEngineOptimizedImpl(String peerHost, int peerPort,
                     org.mozilla.jss.crypto.X509Certificate localCert,
                     org.mozilla.jss.crypto.PrivateKey localKey) {
        super(peerHost, peerPort, localCert, localKey);

        peer_info = peerHost + ":" + peerPort;

        logger.debug("JSSEngine: constructor(" + peerHost + ", " + peerPort + ", " + localCert + ", " + localKey + ")");
    }

    private void init() throws SSLException {
        logger.debug("JSSEngine: init()");

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
        applyConfig();

        // Apply hostname information (via setURL).
        applyHosts();

        // Apply TrustManager(s) information for validating the peer's
        // certificate.
        applyTrustManagers();
    }

    private void createBuffers() {
        logger.debug("JSSEngine: createBuffers()");

        // If the buffers exist, destroy them and recreate.
        if (read_buf != null) {
            JByteBuffer.Free(read_buf);
        }
        read_buf = JByteBuffer.Create(false);

        if (write_buf != null) {
            JByteBuffer.Free(write_buf);
        }
        write_buf = JByteBuffer.Create(true);
    }

    private void createBufferFD() throws SSLException {
        logger.debug("JSSEngine: createBufferFD()");

        // Create the basis for the ssl_fd from the pair of buffers.
        PRFDProxy fd;
        if (peer_info != null && peer_info.length() != 0) {
            fd = PR.NewByteBufferPRFD(read_buf, write_buf, peer_info.getBytes());
        } else {
            fd = PR.NewByteBufferPRFD(read_buf, write_buf, null);
        }

        if (fd == null) {
            throw new SSLException("Error creating buffer-backed PRFileDesc.");
        }

        SSLFDProxy model = null;
        if (as_server) {
            model = getServerTemplate(cert, key);
        }

        // Initialize ssl_fd from the model Buffer-backed PRFileDesc.
        ssl_fd = SSL.ImportFD(model, fd);
        closed_fd = false;

        // Turn on SSL Alert Logging for the ssl_fd object.
        int ret = SSL.EnableAlertLogging(ssl_fd);
        if (ret == SSL.SECFailure) {
            throw new SSLException("Unable to enable SSL Alert Logging on this SSLFDProxy instance.");
        }

        ret = SSL.EnableHandshakeCallback(ssl_fd);
        if (ret == SSL.SECFailure) {
            throw new SSLException("Unable to enable SSL Handshake Callback on this SSLFDProxy instance.");
        }

        // Pass this ssl_fd to the session object so that we can use
        // SSL methods to invalidate the session.
    }

    private void initClient() throws SSLException {
        logger.debug("JSSEngine: initClient()");

        if (cert != null && key != null) {
            logger.debug("JSSEngine.initClient(): Enabling client auth: " + cert);
            ssl_fd.SetClientCert(cert);
            if (SSL.AttachClientCertCallback(ssl_fd) != SSL.SECSuccess) {
                throw new SSLException("Unable to attach client certificate auth callback.");
            }
        }
    }

    private void initServer() throws SSLException {
        logger.debug("JSSEngine: initServer()");

        // The only time cert and key are required are when we're creating a
        // server SSLEngine.
        if (cert == null || key == null) {
            throw new IllegalArgumentException("JSSEngine: must be initialized with server certificate and key!");
        }

        logger.debug("JSSEngine.initServer(): " + cert);
        logger.debug("JSSEngine.initServer(): " + key);

        session.setLocalCertificates(new PK11Cert[]{ cert } );

        // Create a small session cache.
        //
        // TODO: Make this configurable.
        initializeSessionCache(1, 100, null);

        configureClientAuth();
    }

    private void configureClientAuth() throws SSLException {
        logger.debug("SSLFileDesc: " + ssl_fd);

        // Only specify these on the server side as they affect what we
        // want from the remote peer in NSS. In the server case, this is
        // client auth, but if we were to set these on the client, it would
        // affect server auth.
        if (SSL.OptionSet(ssl_fd, SSL.REQUEST_CERTIFICATE, want_client_auth || need_client_auth ? 1 : 0) == SSL.SECFailure) {
            throw new SSLException("Unable to configure SSL_REQUEST_CERTIFICATE option: " + errorText(PR.GetError()));
        }

        if (SSL.OptionSet(ssl_fd, SSL.REQUIRE_CERTIFICATE, need_client_auth ? SSL.REQUIRE_ALWAYS : 0) == SSL.SECFailure) {
            throw new SSLException("Unable to configure SSL_REQUIRE_CERTIFICATE option: " + errorText(PR.GetError()));
        }
    }

    protected void reconfigureClientAuth() {
        if (ssl_fd == null || !as_server) {
            return;
        }

        try {
            configureClientAuth();
        } catch (SSLException se) {
            // We cannot throw SSLException from this helper because it
            // is called from setNeedClientAuth and setWantClientAuth,
            // both of which don't disclose SSLException.
            throw new RuntimeException(se.getMessage(), se);
        }
    }

    private void applyCiphers() throws SSLException {
        logger.debug("JSSEngine: applyCiphers()");
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
                // logger.warn("Unable to set cipher suite preference for " + suite.name() + ": " + errorText(PR.GetError()));
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
                logger.warn("Unable to enable cipher suite " + suite + ": " + errorText(PR.GetError()));
            } else {
                logger.debug("Enabled cipher suite " + suite + ": " + errorText(PR.GetError()));
            }
        }
    }

    private void applyProtocols() throws SSLException {
        logger.debug("JSSEngine: applyProtocols() min_protocol=" + min_protocol + " max_protocol=" + max_protocol);
        // Enable the protocols only when both a maximum and minimum protocol
        // version are specified.
        if (min_protocol == null || max_protocol == null) {
            logger.debug("JSSEngine: applyProtocols() - missing min_protocol or max_protocol; using defaults");
            return;
        }

        // We should bound this range by crypto-policies in the future to
        // match the current behavior.
        SSLVersionRange vrange = new SSLVersionRange(min_protocol, max_protocol);
        if (SSL.VersionRangeSet(ssl_fd, vrange) == SSL.SECFailure) {
            throw new SSLException("Unable to set version range: " + errorText(PR.GetError()));
        }
    }

    private void applyConfig() throws SSLException {
        logger.debug("JSSEngine: applyConfig()");
        for (Integer key : config.keySet()) {
            Integer value = config.get(key);

            logger.debug("Setting configuration option: " + key + "=" + value);
            if (SSL.OptionSet(ssl_fd, key, value) != SSL.SECSuccess) {
                throw new SSLException("Unable to set configuration value: " + key + "=" + value);
            }
        }
    }

    private void applyHosts() throws SSLException {
        logger.debug("JSSEngine: applyHosts()");

        // This is most useful for the client end of the connection; this
        // specifies what to match the server's certificate against.
        if (hostname != null) {
            if (SSL.SetURL(ssl_fd, hostname) == SSL.SECFailure) {
                throw new SSLException("Unable to configure server hostname: " + errorText(PR.GetError()));
            }
        }
    }

    private void applyTrustManagers() throws SSLException {
        logger.debug("JSSEngine: applyTrustManagers()");

        // If none have been specified, exit early.
        if (trust_managers == null || trust_managers.length == 0) {
            // Use the default NSS certificate authentication handler. We
            // don't need to do anything to use it.
            logger.debug("JSSEngine: no TrustManagers to apply.");
            return;
        }

        // Determine which configuration to use for checking certificates. Our
        // options are a Native trust manager (most performant) or using a set
        // of X509TrustManagers.
        if (trust_managers.length == 1 && trust_managers[0] instanceof JSSNativeTrustManager) {
            // This is a dummy TrustManager. It signifies that we should call
            // SSL.ConfigJSSDefaultCertAuthCallback(...) on this SSL
            // PRFileDesc pointer, letting us utilize the same certificate
            // validation logic that SSLSocket had.
            logger.debug("JSSEngine: applyTrustManagers() - adding Native TrustManager");
            if (SSL.ConfigJSSDefaultCertAuthCallback(ssl_fd) == SSL.SECFailure) {
                throw new SSLException("Unable to configure JSSNativeTrustManager on this JSSengine: " + errorText(PR.GetError()));
            }
            return;
        }

        if (as_server) {
            // We need to manually invoke the async cert auth handler. However,
            // SSLFDProxy makes this easy for us: our CertAuthHandler derives
            // from Runnable, so we can reuse it here as well. We can create
            // it ahead of time though. In this case, checkNeedCertValidation()
            // is never called.
            ssl_fd.handler = new CertValidationTask(ssl_fd);

            if (SSL.ConfigSyncTrustManagerCertAuthCallback(ssl_fd) == SSL.SECFailure) {
                throw new SSLException("Unable to configure TrustManager validation on this JSSengine: " + errorText(PR.GetError()));
            }
        } else {
            // Otherwise, we need a hook from NSS into the SSLFDProxy.
            //
            // This hook executes all TrustManagers and if any exception
            // occurs, we'll turn it into the proper response within NSS.
            if (SSL.ConfigAsyncTrustManagerCertAuthCallback(ssl_fd) == SSL.SECFailure) {
                throw new SSLException("Unable to configure TrustManager validation on this JSSengine: " + errorText(PR.GetError()));
            }
        }
    }

    public void beginHandshake() throws SSLException {
        logger.debug("JSSEngine: beginHandshake()");

        // We assume beginHandshake(...) is the entry point for initializing
        // the buffer. In particular, wrap(...) / unwrap(...) *MUST* call
        // beginHandshake(...) if ssl_fd == null.

        // ssl_fd == null <-> we've not initialized anything yet.

        // TLS begins with the client sending a CLIENT_HELLO to the server;
        // this means that the server needs to unwrap first and the client
        // needs to wrap first; hence unwrap = as_server. However, if we're
        // trying to renegotiate this changes. See when ssl_fd != null below.
        boolean unwrap = as_server;

        if (ssl_fd == null) {
            // Initialize and create ssl_fd. Throws various RuntimeExceptions
            // when creation and configuration fails.
            init();
            assert(ssl_fd != null);

            // Reset the handshake status, using the new socket and
            // configuration which was just created. This ensures that
            // we'll attempt to handshake when ForceHandshake is called.
            if (SSL.ResetHandshake(ssl_fd, as_server) == SSL.SECFailure) {
                throw new RuntimeException("Unable to begin handshake: " + errorText(PR.GetError()));
            }
        } else {
            // When ssl_fd exists, we need to re-handshake. Usually, the
            // server initiates the conversation (especially when we want
            // to upgrade to requiring client auth from not requiring it).
            //
            // This means that when we're a (as_server == true), we should
            // now wrap, rather than unwrap. So, negate unwrap.
            unwrap = !as_server;

            // TLS v1.3 differs from all previous versions in that it removed
            // the ability to completely rehandshake. This makes the first
            // portion more complicated than the latter.
            if (session.getSSLVersion() == SSLVersion.TLS_1_3) {
                // We only send the certificate request as a server when we
                // need client auth. Otherwise, we'll have to issue a rekey
                // request.
                boolean send_certificate_request = as_server && need_client_auth;
                if (send_certificate_request) {
                    if (SSL.SendCertificateRequest(ssl_fd) == SSL.SECFailure) {
                        throw new RuntimeException("Unable to issue certificate request on TLSv1.3: " + errorText(PR.GetError()));
                    }
                } else {
                    // Our best guess at what the user wants is to update
                    // their keys. They don't need client authentication but
                    // they explicitly called beginHandshake() again.
                    if (SSL.KeyUpdate(ssl_fd, false) == SSL.SECFailure) {
                        throw new RuntimeException("Unable to request a new key on TLSv1.3: " + errorText(PR.GetError()));
                    }
                }
            } else {
                // On older protocol versions, this is easier: just issue a
                // new handshake request. This is different from
                // ResetHandshake as for security reasons, the semantics have
                // to differ.
                if (SSL.ReHandshake(ssl_fd, true) == SSL.SECFailure) {
                    throw new RuntimeException("Unable to rehandshake: " + errorText(PR.GetError()));
                }
            }
        }

        // Make sure we reset the handshake completion status in order for the
        // callback to work correctly.
        ssl_fd.handshakeComplete = false;

        // This leaves setting internal variables for HandshakeStatus and
        // the reporting up from SSLEngine.
        if (unwrap) {
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        } else {
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;
        }

        // We've begun a new handshake; make sure we step it and reset
        // our unknown state count to zero.
        step_handshake = true;
        unknown_state_count = 0;
    }

    public void closeInbound() {
        logger.debug("JSSEngine: closeInbound()");

        is_inbound_closed = true;
    }

    public void closeOutbound() {
        logger.debug("JSSEngine: closeOutbound()");

        is_outbound_closed = true;
    }

    private void markClosed() {
        if (is_inbound_closed) {
            PR.Shutdown(ssl_fd, PR.SHUTDOWN_RCV);
        }

        if (is_outbound_closed) {
            PR.Shutdown(ssl_fd, PR.SHUTDOWN_SEND);
        }
    }

    public String getHostname() {
        return hostname;
    }

    public Runnable getDelegatedTask() {
        logger.debug("JSSEngine: getDelegatedTask()");

        checkNeedCertValidation();

        return task;
    }

    private boolean checkNeedCertValidation() {
        logger.debug("JSSEngine: checkNeedCertValidation()");
        if (task != null) {
            if (!task.finished) {
                // Already created runnable task; exit with true status to
                // show it still needs to be run.
                logger.debug("JSSEngine: checkNeedCertValidation() - task not done");
                return true;
            }

            logger.debug("JSSEngine: checkNeedCertValidation() - task done with code " + task.result);

            // Since the task has finished, we now need to inform NSS about
            // the results of our certificate validation step.
            if (SSL.AuthCertificateComplete(ssl_fd, task.result) != SSL.SECSuccess) {
                String msg = "Got unexpected failure finishing cert ";
                msg += "authentication in NSS. Returned code ";
                msg += task.result;
                throw new RuntimeException(msg);
            }

            // After checking certificates, our best guess will be that we
            // need to run wrap again. This is because we either need to
            // inform the caller of an error that occurred, or continue the
            // handshake. Worst case, we'll call updateHandshakeState() and
            // it'll correct our mmistake eventually.

            logger.debug("JSSEngine: checkNeedCertValidation() - task done, removing");

            task = null;
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;
            ssl_fd.needCertValidation = false;

            return false;
        }

        if (ssl_fd == null) {
            // If we don't have a SSLFDProxy instance, nothing we can do but
            // skip checking if the task exists. Return false to show that
            // we don't yet have a runnable task.
            logger.debug("JSSEngine: checkNeedCertValidation() - no ssl_fd");
            return false;
        }

        if (!ssl_fd.needCertValidation) {
            // We don't yet need certificate validation. Don't create a
            // runnable task for now.
            logger.debug("JSSEngine: checkNeedCertValidation() - no need for cert validation");
            return false;
        }

        logger.debug("JSSEngine: checkNeedCertValidation() - creating task");

        // OK, time to create our runnable task.
        task = new CertValidationTask(ssl_fd);

        // Update our handshake state so we know what to do next.
        handshake_state = SSLEngineResult.HandshakeStatus.NEED_TASK;

        return true;
    }

    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        logger.debug("JSSEngine: getHandshakeStatus()");

        // If task is NULL, we need to update the state to check if the
        // task has been "run". Even if it isn't, it would be good to
        // update the status here as well. However, we DO NOT want to
        // call updateHandshakeState() in the event we have a task to
        // run: we need to run it still!
        if (checkNeedCertValidation()) {
            return handshake_state;
        }

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

    private int computeSize(ByteBuffer[] buffers, int offset, int length) throws IllegalArgumentException {
        logger.debug("JSSEngine: computeSize()");
        int result = 0;

        if (buffers == null || buffers.length == 0) {
            logger.debug("JSSEngine.computeSize(): no buffers - result=" + result);
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
                logger.debug("JSSEngine.computeSize(): null first buffer - result=" + result);
                return result;
            }

            if (buffers[index] == null) {
                throw new IllegalArgumentException("Buffer at index " + index + " is null.");
            }

            result += buffers[index].remaining();
        }

        logger.debug("JSSEngine.computeSize(): result=" + result);

        return result;
    }

    private int putData(byte[] data, ByteBuffer[] buffers, int offset, int length) {
        logger.debug("JSSEngine: putData()");
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

            // Compute the size of the put: it is the minimum of the space
            // remaining in this buffer and the bytes remaining in the data
            // array.
            int put_size = buffers[buffer_index].remaining();
            if (put_size > (data.length - data_index)) {
                put_size = data.length - data_index;
            }

            buffers[buffer_index].put(data, data_index, put_size);
            data_index += put_size;
        }

        return data_index;
    }

    private SSLException checkSSLAlerts() {
        logger.debug("JSSEngine: Checking inbound and outbound SSL Alerts. Have " + ssl_fd.inboundAlerts.size() + " inbound and " + ssl_fd.outboundAlerts.size() + " outbound alerts.");

        // Prefer inbound alerts to outbound alerts.
        while (ssl_fd.inboundOffset < ssl_fd.inboundAlerts.size()) {
            SSLAlertEvent event = ssl_fd.inboundAlerts.get(ssl_fd.inboundOffset);
            ssl_fd.inboundOffset += 1;

            if (event.getLevelEnum() == SSLAlertLevel.WARNING && event.getDescriptionEnum() == SSLAlertDescription.CLOSE_NOTIFY) {
                logger.debug("Got inbound CLOSE_NOTIFY alert");
                closeInbound();
            }

            logger.debug("JSSEngine: Got inbound alert: " + event);

            SSLException exception = event.toException();
            if (exception != null) {
                return exception;
            }
        }

        while (ssl_fd.outboundOffset < ssl_fd.outboundAlerts.size()) {
            SSLAlertEvent event = ssl_fd.outboundAlerts.get(ssl_fd.outboundOffset);
            ssl_fd.outboundOffset += 1;

            if (event.getLevelEnum() == SSLAlertLevel.WARNING && event.getDescriptionEnum() == SSLAlertDescription.CLOSE_NOTIFY) {
                logger.debug("Sent outbound CLOSE_NOTIFY alert.");
                closeOutbound();
            }

            logger.debug("JSSEngine: Got outbound alert: " + event);

            SSLException exception = event.toException();
            if (exception != null) {
                return exception;
            }
        }

        return null;
    }

    private void updateHandshakeState() {
        logger.debug("JSSEngine: updateHandshakeState()");

        // If we've previously seen an exception, we should just return
        // here; there's already an alert on the wire, so there's no point
        // in checking for new ones and/or stepping the handshake: it has
        // already failed.
        if (seen_exception) {
            return;
        }

        // If we're already done, we should check for SSL ALerts.
        if (!step_handshake && handshake_state == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            logger.debug("JSSEngine.updateHandshakeState() - not handshaking");
            unknown_state_count = 0;

            ssl_exception = checkSSLAlerts();
            seen_exception = (ssl_exception != null);
            return;
        }

        // If we've previously finished handshaking, then move to
        // NOT_HANDSHAKING. Now is also a good time to check for any
        // alerts.
        if (!step_handshake && handshake_state == SSLEngineResult.HandshakeStatus.FINISHED) {
            logger.debug("JSSEngine.updateHandshakeState() - FINISHED to NOT_HANDSHAKING");
            handshake_state = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

            unknown_state_count = 0;

            ssl_exception = checkSSLAlerts();
            seen_exception = (ssl_exception != null);
            return;
        }

        logger.debug("Stepping handshake? step_handshake=" + step_handshake);

        int pre_read_capacity = JByteBuffer.Capacity(read_buf);
        int pre_write_capacity = JByteBuffer.Capacity(write_buf);
        boolean need_wrap = handshake_state == SSLEngineResult.HandshakeStatus.NEED_WRAP;
        boolean need_unwrap = handshake_state == SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        boolean was_finished = ssl_fd.handshakeComplete;

        if (!step_handshake) {
            // Don't bother calling SSL_ForceHandshake in the event of no
            // capacity.
            return;
        }

        if ((need_unwrap && pre_read_capacity == 0) || (need_wrap && pre_write_capacity == 0)) {
            logger.debug("pre_read_capacity == " + pre_read_capacity + " || pre_write_capacity == " + pre_write_capacity);
            unknown_state_count += 1;
            if (unknown_state_count >= 4) {
                if (handshake_state == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    handshake_state = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
                } else {
                    handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                }
                unknown_state_count = 1;
            }

            return;
        }

        // Since we're not obviously done handshaking, and the last time we
        // were called, we were still handshaking, step the handshake.
        logger.debug("JSSEngine.updateHandshakeState() - forcing handshake");
        if (SSL.ForceHandshake(ssl_fd) == SSL.SECFailure) {
            int error_value = PR.GetError();

            if (error_value != PRErrors.WOULD_BLOCK_ERROR) {
                logger.debug("JSSEngine.updateHandshakeState() - FATAL " + getStatus());

                ssl_exception = new SSLHandshakeException("Error duing SSL.ForceHandshake() :: " + errorText(error_value));
                seen_exception = true;

                handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                return;
            }
        }

        if (need_wrap && JByteBuffer.Capacity(write_buf) == 0 && pre_write_capacity > 0) {
            // When we just wrapped, but we're out of capacity, assume we
            // need to wrap again to proceed further.
            unknown_state_count = 0;
            return;
        }

        // We use handshakeComplete because it is a reliable indicator of
        // when the handshake is complete, unlike SecurityStatus. Notably,
        // handshakeComplete == true only when the FINISHED message has
        // been confirmed by both parties.
        if (was_finished && ssl_fd.handshakeComplete && (need_wrap || need_unwrap)) {
            logger.debug("JSSEngine.updateHandshakeState() - handshakeComplete is " + ssl_fd.handshakeComplete + ", so we've just finished handshaking");
            step_handshake = false;
            handshake_state = SSLEngineResult.HandshakeStatus.FINISHED;
            unknown_state_count = 0;

            // Only update peer certificate chain when we've finished
            // handshaking.
            try {
                PK11Cert[] peer_chain = SSL.PeerCertificateChain(ssl_fd);
                session.setPeerCertificates(peer_chain);
            } catch (Exception e) {
                String msg = "Unable to get peer's certificate chain: ";
                msg += e.getMessage();

                seen_exception = true;
                ssl_exception = new SSLException(msg, e);
            }

            // Also update our session information here.
            session.refreshData();

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
        logger.debug("JSSEngine: isHandshakeFinished()");
        return (handshake_state == SSLEngineResult.HandshakeStatus.FINISHED ||
                (ssl_fd != null && handshake_state == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING));
    }

    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws IllegalArgumentException, SSLException {
        if (ssl_fd == null) {
            beginHandshake();
        }

        int available = src.remaining();
        int capacity = computeSize(dsts, offset, length);

        // Before going much further, check to see if we need to run a
        // delegated task. So far, the only delegated tasks we have are
        // for checking TrustManagers.
        if (checkNeedCertValidation()) {
            return new SSLEngineResult(SSLEngineResult.Status.OK, handshake_state, 0, 0);
        }

        logger.debug("Setting read buffer: " + src);
        JByteBuffer.SetBuffer(read_buf, src);
        try {
            return unwrap(available, dsts, offset, length, capacity);
        } finally {
            JByteBuffer.ClearBuffer(read_buf);
        }
    }

    public SSLEngineResult unwrap(int src_capacity, ByteBuffer[] dsts, int offset, int length, int dst_capacity) throws IllegalArgumentException, SSLException {
        logger.debug("JSSEngine: unwrap(ssl_fd=" + ssl_fd + ")");

        // In this method, we're taking the network wire contents of src and
        // passing them as the read side of our buffer. If there's any data
        // for us to read from the remote peer (via ssl_fd), we place it in
        // the various dsts.
        //
        // However, we also need to detect if the handshake is still ongoing;
        // if so, we can't send data (from src) until then.

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

        // wire_data is the number of bytes from src we've written into
        // read_buf.
        int wire_data = 0;

        // Actual amount of data written to the buffer.
        int app_data = 0;

        // Whether or not the handshake was complete prior to the
        // updateHandshakeState() call.
        boolean handshake_already_finished = ssl_fd.handshakeComplete;

        // In the above, we should always try to read and write data. Check to
        // see if we need to step our handshake process or not.
        updateHandshakeState();

        byte[] app_buffer = PR.Read(ssl_fd, dst_capacity);
        int error = PR.GetError();
        logger.debug("JSSEngine.unwrap() - " + app_buffer + " error=" + errorText(error));
        if (app_buffer != null) {
            app_data = putData(app_buffer, dsts, offset, length);
        } else if (dst_capacity > 0) {
            // There are two scenarios we need to ignore here:
            //  1. WOULD_BLOCK_ERRORs are safe, because we're expecting
            //     not to block. Usually this means we don't have space
            //     to write any more data.
            //  2. SOCKET_SHUTDOWN_ERRORs are safe, because if the
            //     underling cause was fatal, we'd catch it after exiting
            //     the do-while loop, in checkSSLAlerts().
            if (error != 0 && error != PRErrors.WOULD_BLOCK_ERROR && error != PRErrors.SOCKET_SHUTDOWN_ERROR) {
                ssl_exception = new SSLException("Unexpected return from PR.Read(): " + errorText(error));
                seen_exception = true;
            }
        }

        wire_data = JByteBuffer.ClearBuffer(read_buf);

        if (seen_exception == false && ssl_exception == null) {
            ssl_exception = checkSSLAlerts();
            seen_exception = (ssl_exception != null);
        }

        // Before we return, check if an exception occurred and throw it if
        // one did.
        if (ssl_exception != null) {
            logger.info("JSSEngine.unwrap() - Got SSLException: " + ssl_exception);
            SSLException excpt = ssl_exception;
            ssl_exception = null;
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;
            tryCleanup();
            throw excpt;
        }

        SSLEngineResult.Status handshake_status = SSLEngineResult.Status.OK;


        if (is_inbound_closed) {
            logger.debug("Socket is currently closed.");
            handshake_status = SSLEngineResult.Status.CLOSED;
        } else if (handshake_already_finished && app_data == 0 && src_capacity > 0) {
            logger.debug("Got underflow condition");
            handshake_status = SSLEngineResult.Status.BUFFER_UNDERFLOW;
        }

        // Need a way to introspect the open/closed state of the TLS
        // connection.

        logger.debug("JSSEngine.unwrap() - Finished");
        logger.debug(" - Status: " + handshake_status);
        logger.debug(" - Handshake State: " + handshake_state);
        logger.debug(" - wire_data: " + wire_data);
        logger.debug(" - app_data: " + app_data);

        tryCleanup();
        return new SSLEngineResult(handshake_status, handshake_state, wire_data, app_data);
    }

    public int writeData(ByteBuffer[] srcs, int offset, int length) {
        logger.debug("JSSEngine: writeData()");
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
        //
        // When we don't perform an actual NSPR write call, make a dummy
        // invocation to ensure we always attempt to flush these buffers.
        int data_length = 0;

        int index = offset;
        int max_index = offset + length;

        boolean attempted_write = false;

        while (index < max_index) {
            // If we don't have any remaining bytes in this buffer, skip it.
            if (srcs[index] == null || srcs[index].remaining() <= 0) {
                logger.debug("JSSEngine: skipping null buffer at index=" + index);
                index += 1;
                continue;
            }
            logger.debug("JSSEngine.writeData(): index=" + index + " max_index=" + max_index);

            // We expect (i.e., need to construct a buffer) to write up to
            // this much. Note that this is non-zero since we're taking the
            // max here and we guarantee with the previous statement that
            // srcs[index].remaining() > 0. There's no point in getting more
            // than BUFFER_SIZE bytes either; so cap at the minimum of the
            // two sizes.
            int expected_write = Math.min(srcs[index].remaining(), BUFFER_SIZE);

            // Get data from our current srcs[index] buffer.
            byte[] app_data = new byte[expected_write];
            srcs[index].get(app_data);

            // Actual amount written. Since this is a PR.Write call, mark
            // attempted_write.
            int this_write = PR.Write(ssl_fd, app_data);
            attempted_write = true;

            // Reset our buffer's position in event of sub-optimal write.
            if (this_write < expected_write) {
                int pos = srcs[index].position();

                // When this_write < 0, we want to reset to the beginning
                // because we assume we haven't written any data due to an
                // error before writing.
                int delta = expected_write - Math.max(0, this_write);

                srcs[index].position(pos - delta);
            }

            logger.debug("JSSEngine.writeData(): this_write=" + this_write);
            if (this_write < 0) {
                int error = PR.GetError();
                if (error == PRErrors.SOCKET_SHUTDOWN_ERROR) {
                    logger.debug("NSPR reports outbound socket is shutdown.");
                    is_outbound_closed = true;
                } else if (error != PRErrors.WOULD_BLOCK_ERROR) {
                    throw new RuntimeException("Unable to write to internal ssl_fd: " + errorText(PR.GetError()));
                }

                break;
            }

            data_length += this_write;

            if (this_write < expected_write) {
                // If we didn't get an error but we got less than our expected
                // write, it is best to exit to give us time to drain the
                // buffers before attempting another write. We're guaranteed
                // to be called again because we wrote a non-zero amount here.
                break;
            }
        }

        // When we didn't call PR.Write, invoke a dummy call to PR.Write to
        // ensure we always attempt to write to push data from NSS's internal
        // buffers into our network buffers.
        if (!attempted_write) {
            PR.Write(ssl_fd, null);
        }

        logger.debug("JSSEngine.writeData(): data_length=" + data_length);

        return data_length;
    }

    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws IllegalArgumentException, SSLException {
        if (ssl_fd == null) {
            beginHandshake();
        }

        if (ssl_fd.handshakeComplete && srcs != null && dst != null) {
            int available = computeSize(srcs, offset, length);
            int capacity = dst.remaining();

            if (available > capacity && capacity < BUFFER_SIZE) {
                logger.error("wrap - BUFFER_OVERFLOW: " + available + " vs " + capacity);
                return new SSLEngineResult(SSLEngineResult.Status.BUFFER_OVERFLOW, handshake_state, 0, 0);
            }
        }

        // Before going much further, check to see if we need to run a
        // delegated task. So far, the only delegated tasks we have are
        // for checking TrustManagers.
        if (checkNeedCertValidation()) {
            return new SSLEngineResult(SSLEngineResult.Status.OK, handshake_state, 0, 0);
        }

        logger.debug("Setting write buffer: " + dst);

        JByteBuffer.SetBuffer(write_buf, dst);
        try {
            return wrap(srcs, offset, length);
        } finally {
            JByteBuffer.ClearBuffer(write_buf);
        }
    }

    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length) throws IllegalArgumentException, SSLException {
        logger.debug("JSSEngine: wrap(ssl_fd=" + ssl_fd + ")");
        // In this method, we're taking the application data from the various
        // srcs and writing it to the remote peer (via ssl_fd). If there's any
        // data for us to send to the remote peer, we place it in dst.
        //
        // However, we also need to detect if the handshake is still ongoing;
        // if so, we can't send data (from src) until then.

        // Order of operations:
        //  1. Check if either end of the handshake is closed
        //  2. Step the handshake
        //  3. Write data from srcs to ssl_fd

        // Actual amount of data read from srcs (and written to ssl_fd). This
        // is determined by the PR.Write(...) call on ssl_fd.
        int app_data = 0;

        // wire_data is the number of bytes written to dst. This is bounded
        // above by two fields: the number of bytes we can read from
        // write_buf, and the size of dst, if present.
        int wire_data = 0;

        if (is_inbound_closed) {
            closeOutbound();
        }

        // We have to wait until we've gotten buffers in order to mark the
        // underlying socket as closed. Otherwise, we wouldn't catch the
        // resulting exception that gets sent on the wire.
        markClosed();

        // First we try updating the handshake state.
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
                logger.debug("Setting state to FINISHED because of previous exception and in wrap().");
                handshake_state = SSLEngineResult.HandshakeStatus.FINISHED;
            }
        }

        // Try writing data from srcs to the other end of the connection. Note
        // that we always attempt this, even if the handshake isn't yet marked
        // as finished. This is because we need the call to PR.Write(...) to
        // tell if an alert is getting sent.
        app_data = writeData(srcs, offset, length);
        logger.debug("JSSEngine.wrap(): wrote " + app_data + " from srcs to buffer.");

        wire_data = JByteBuffer.ClearBuffer(write_buf);

        if (seen_exception == false && ssl_exception == null) {
            ssl_exception = checkSSLAlerts();
            seen_exception = (ssl_exception != null);
        }

        // Before we return, check if an exception occurred and throw it if
        // one did.
        if (ssl_exception != null) {
            logger.info("JSSEngine.wrap() - Got SSLException: " + ssl_exception);
            SSLException excpt = ssl_exception;
            ssl_exception = null;
            cleanup();
            throw excpt;
        }

        // Need a way to introspect the open/closed state of the TLS
        // connection.

        SSLEngineResult.Status handshake_status = SSLEngineResult.Status.OK;

        if (ssl_exception == null && seen_exception) {
            logger.debug("Seen and processed exception; closing inbound and outbound because this was the last wrap(...)");
            closeInbound();
            closeOutbound();
        }

        if (is_outbound_closed) {
            logger.debug("Socket is currently closed.");
            handshake_status = SSLEngineResult.Status.CLOSED;
        }

        logger.debug("JSSEngine.wrap() - Finished");
        logger.debug(" - Status: " + handshake_status);
        logger.debug(" - Handshake State: " + handshake_state);
        logger.debug(" - wire_data: " + wire_data);
        logger.debug(" - app_data: " + app_data);

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
        logger.debug("JSSEngine: tryCleanup()");
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
        logger.debug("JSSEngine: cleanup()");

        if (!is_inbound_closed) {
            logger.debug("JSSEngine: cleanup() - closing opened inbound socket");
            closeInbound();
        }

        if (!is_outbound_closed) {
            logger.debug("JSSEngine: cleanup() - closing opened outbound socket");
            closeOutbound();
        }

        // Then clean up the NSS state.
        cleanupSSLFD();
    }

    private void cleanupSSLFD() {
        if (!closed_fd && ssl_fd != null) {
            try {
                SSL.RemoveCallbacks(ssl_fd);
                PR.Close(ssl_fd);
                ssl_fd.close();
            } catch (Exception e) {
                logger.debug("Got exception trying to cleanup SSLFD: " + e.getMessage());
            } finally {
                closed_fd = true;
            }
        }

        if (read_buf != null) {
            JByteBuffer.Free(read_buf);
            read_buf = null;
        }

        if (write_buf != null) {
            JByteBuffer.Free(write_buf);
            write_buf = null;
        }
    }

    private class CertValidationTask extends CertAuthHandler {
        public CertValidationTask(SSLFDProxy fd) {
            super(fd);
        }

        public String findAuthType(SSLFDProxy ssl_fd, PK11Cert[] chain) throws Exception {
            SSLPreliminaryChannelInfo info = SSL.GetPreliminaryChannelInfo(ssl_fd);
            if (info == null) {
                String msg = "Expected non-null result from GetPreliminaryChannelInfo!";
                throw new RuntimeException(msg);
            }

            if (!info.haveProtocolVersion()) {
                String msg = "Expected SSLPreliminaryChannelInfo (";
                msg += info + ") to have protocol information.";
                throw new RuntimeException(msg);
            }

            if (!info.haveCipherSuite()) {
                String msg = "Expected SSLPreliminaryChannelInfo (";
                msg += info + ") to have cipher suite information.";
                throw new RuntimeException(msg);
            }

            SSLVersion version = info.getProtocolVersion();
            SSLCipher suite = info.getCipherSuite();

            if (version.value() < SSLVersion.TLS_1_3.value()) {
                // When we're doing a TLSv1.2 or earlier protocol exchange,
                // we can simply check the cipher suite value for the
                // authentication type.
                if (suite.requiresRSACert()) {
                    // Java expects RSA_EXPORT to be handled properly.
                    // However, rather than checking the actual bits in
                    // the RSA certificate, return it purely based on
                    // cipher suite name. In modern reality, these ciphers
                    // should _NEVER_ be negotiated!
                    if (suite.name().contains("RSA_EXPORT")) {
                        return "RSA_EXPORT";
                    }

                    return "RSA";
                } else if (suite.requiresECDSACert()) {
                    return "ECDSA";
                } else if (suite.requiresDSSCert()) {
                    // Notably, DSS is the same as DSA, but the suite names
                    // all use DSS while the JDK uses DSA.
                    return "DSA";
                }
                // Implicit else: authType == null, causing TrustManager
                // check to fail.
            } else {
                // For TLSv1.3 and any later protocols, we can't rely on
                // the above requires() checks, because the actual
                // signature type depends on the type of the certificate
                // provided. This makes the TrustManager field redundant,
                // but yet we still have to provide it.
                if (chain != null && chain.length > 0 && chain[0] != null) {
                    PK11Cert cert = chain[0];
                    PublicKey key = cert.getPublicKey();
                    return key.getAlgorithm();
                }
                // Implicit else here and above: authType == null, which
                // will cause the TrustManager check to fail.
            }

            return null;
        }

        public int check(SSLFDProxy fd) {
            // Needs to be available for assignException() below.
            PK11Cert[] chain = null;

            try {
                chain = SSL.PeerCertificateChain(fd);
                String authType = findAuthType(fd, chain);
                logger.debug("CertAuthType: " + authType);

                if (chain == null || chain.length == 0) {
                    // When the chain is NULL, we'd always fail in the
                    // TrustManager calls, beacuse they expect a non-NULL,
                    // non-empty chain. However, this is sometimes desired,
                    // for instance, if we requested the peer to provide a
                    // certificate chain and they didn't.
                    if (as_server == true && !need_client_auth) {
                        // Since we're a server validating the client's
                        // chain (and they didn't provide one), we should
                        // ignore it instead of forcing the problem.
                        logger.debug("No client certificate chain and client cert not needed.");
                        return 0;
                    }
                }

                for (X509TrustManager tm : trust_managers) {
                    // X509ExtendedTrustManager lets the TM access the
                    // SSLEngine while validating certificates. Otherwise,
                    // the X509TrustManager doesn't have access to that
                    // parameter. Facilitate it if possible.
                    if (tm instanceof X509ExtendedTrustManager) {
                        X509ExtendedTrustManager etm = (X509ExtendedTrustManager) tm;
                        if (as_server) {
                            etm.checkClientTrusted(chain, authType, JSSEngineOptimizedImpl.this);
                        } else {
                            etm.checkServerTrusted(chain, authType, JSSEngineOptimizedImpl.this);
                        }
                    } else {
                        if (as_server) {
                            tm.checkClientTrusted(chain, authType);
                        } else {
                            tm.checkServerTrusted(chain, authType);
                        }
                    }
                }
            } catch (Exception excpt) {
                return assignException(excpt, chain);
            }

            return 0;
        }

        private int assignException(Exception excpt, PK11Cert[] chain) {
            int nss_code = Cert.MatchExceptionToNSSError(excpt);

            if (seen_exception) {
                return nss_code;
            }

            String msg = "Got exception while trying to validate ";
            msg += "peer's certificate chain:\n";
            if (chain == null) {
                msg += " - (null chain)\n";
            } else if (chain.length == 0) {
                msg += " - (0 length chain)\n";
            } else {
                for (PK11Cert cert : chain) {
                    msg += " - " + cert + "\n";
                }
            }
            msg += "with given TrustManagers:\n";
            if (trust_managers == null) {
                msg += " - (null TrustManagers)\n";
            } else if (trust_managers.length == 0) {
                msg += " - (0 length TrustManagers)\n";
            } else {
                for (X509TrustManager tm : trust_managers) {
                    msg += " - " + tm + "\n";
                }
            }
            msg += "exception message: " + excpt.getMessage();

            seen_exception = true;
            ssl_exception = new SSLException(msg, excpt);
            return nss_code;
        }
    }
}
