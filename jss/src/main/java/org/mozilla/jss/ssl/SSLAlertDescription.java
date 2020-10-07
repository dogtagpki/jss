/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;

public enum SSLAlertDescription {

    // see lib/ssl/ssl3prot.h in NSS
    CLOSE_NOTIFY                    (0),
    END_OF_EARLY_DATA               (1), // TLS 1.3
    UNEXPECTED_MESSAGE              (10, SSLProtocolException.class),
    BAD_RECORD_MAC                  (20, SSLProtocolException.class),
    DECRYPTION_FAILED               (21, SSLProtocolException.class), // RFC 5246
    RECORD_OVERFLOW                 (22, SSLProtocolException.class), // TLS only
    DECOMPRESSION_FAILURE           (30, SSLProtocolException.class),
    HANDSHAKE_FAILURE               (40, SSLHandshakeException.class),
    NO_CERTIFICATE                  (41, SSLPeerUnverifiedException.class), // SSL3 only, NOT TLS
    BAD_CERTIFICATE                 (42, SSLPeerUnverifiedException.class),
    UNSUPPORTED_CERTIFICATE         (43, SSLPeerUnverifiedException.class),
    CERTIFICATE_REVOKED             (44, SSLPeerUnverifiedException.class),
    CERTIFICATE_EXPIRED             (45, SSLPeerUnverifiedException.class),
    CERTIFICATE_UNKNOWN             (46, SSLPeerUnverifiedException.class),
    ILLEGAL_PARAMETER               (47, SSLProtocolException.class),

    // All alerts below are TLS only.
    UNKNOWN_CA                      (48, SSLPeerUnverifiedException.class),
    ACCESS_DENIED                   (49, SSLHandshakeException.class),
    DECODE_ERROR                    (50, SSLProtocolException.class),
    DECRYPT_ERROR                   (51, SSLProtocolException.class),
    EXPORT_RESTRICTION              (60, SSLHandshakeException.class),
    PROTOCOL_VERSION                (70, SSLHandshakeException.class),
    INSUFFICIENT_SECURITY           (71, SSLHandshakeException.class),
    INTERNAL_ERROR                  (80, SSLProtocolException.class),
    INAPPROPRIATE_FALLBACK          (86, SSLProtocolException.class), // could also be sent for SSLv3
    USER_CANCELED                   (90, SSLProtocolException.class),
    NO_RENEGOTIATION                (100, SSLHandshakeException.class),

    // Alerts for client hello extensions
    MISSING_EXTENSION               (109, SSLHandshakeException.class),
    UNSUPPORTED_EXTENSION           (110, SSLHandshakeException.class),
    CERTIFICATE_UNOBTAINABLE        (111, SSLPeerUnverifiedException.class),
    UNRECOGNIZED_NAME               (112, SSLHandshakeException.class),
    BAD_CERTIFICATE_STATUS_RESPONSE (113, SSLPeerUnverifiedException.class),
    BAD_CERTIFICATE_HASH_VALUE      (114, SSLPeerUnverifiedException.class),
    NO_APPLICATION_PROTOCOL         (120, SSLHandshakeException.class);

    private int id;
    private Class<? extends SSLException> exception;

    private SSLAlertDescription(int id) {
        this.id = id;
    }

    private SSLAlertDescription(int id, Class<? extends SSLException> exception) {
        this(id);
        this.exception = exception;
    }

    public int getID() {
        return id;
    }

    public Class<? extends SSLException> getExceptionClass() {
        return exception;
    }

    public static SSLAlertDescription valueOf(int id) {
        for (SSLAlertDescription description : SSLAlertDescription.class.getEnumConstants()) {
            if (description.id == id) return description;
        }
        return null;
    }
}
