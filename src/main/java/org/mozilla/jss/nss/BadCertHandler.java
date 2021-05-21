package org.mozilla.jss.nss;

/**
 * BadAuthHandler interface enables arbitrary certificate authentication
 * from a NSS cert auth hook.
 *
 * Notably, the return code from check should be a PRErrorCode, else 0.
 * This will be used by NSS to determine the alert to send when closing
 * the connection (in the event of an error).
 *
 * The concern here is that, when this is invoked synchronously, we're
 * called from NSS as called by Java. Certain operations may or may not
 * succeed or work as expected (such as raising an exception, acquiring
 * locks already held, etc.).
 */
public abstract class BadCertHandler implements Runnable {
    /**
     * When invoked via run(), the error code to pass to the
     * check operation.
     */
    public int error;

    /**
     * When invoked via run(), the result of the check
     * operation.
     */
    public int result;

    /**
     * Whether or not the check operation has been executed
     * yet, when invoked via run().
     */
    public boolean finished;

    /**
     * SSLFDProxy instance.
     */
    private SSLFDProxy ssl_fd;

    /**
     * Constructor to store SSLFDProxy, error information.
     *
     * This is useful for implementations which expect to be used
     * via the Runnable interface, instead of called via the
     * synchronous certificate authentication hook in NSS.
     */
    public BadCertHandler(SSLFDProxy fd, int error) {
        ssl_fd = fd;
        this.error = error;
    }

    /**
     * Returns the PRErrorCode the error validating certificate
     * auth, else 0.
     *
     * Note that it is up to the implementer to fetch the certificates
     * (via SSL.PeerCertificateChain(ssl_fd)) and validate them
     * properly.
     *
     * Note that returning 0 here means SECis returned
     */
    public abstract int check(SSLFDProxy fd, int error);

    @Override
    public void run() {
        try {
            result = check(ssl_fd, error);
        } finally {
            finished = true;
        }
    }
}
