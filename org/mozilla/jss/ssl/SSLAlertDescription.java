/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

public enum SSLAlertDescription {

    // see lib/ssl/ssl3prot.h in NSS
    CLOSE_NOTIFY                    (0),
    END_OF_EARLY_DATA               (1), // TLS 1.3
    UNEXPECTED_MESSAGE              (10),
    BAD_RECORD_MAC                  (20),
    DECRYPTION_FAILED               (21), // RFC 5246
    RECORD_OVERFLOW                 (22), // TLS only
    DECOMPRESSION_FAILURE           (30),
    HANDSHAKE_FAILURE               (40),
    NO_CERTIFICATE                  (41), // SSL3 only, NOT TLS
    BAD_CERTIFICATE                 (42),
    UNSUPPORTED_CERTIFICATE         (43),
    CERTIFICATE_REVOKED             (44),
    CERTIFICATE_EXPIRED             (45),
    CERTIFICATE_UNKNOWN             (46),
    ILLEGAL_PARAMETER               (47),

    // All alerts below are TLS only.
    UNKNOWN_CA                      (48),
    ACCESS_DENIED                   (49),
    DECODE_ERROR                    (50),
    DECRYPT_ERROR                   (51),
    EXPORT_RESTRICTION              (60),
    PROTOCOL_VERSION                (70),
    INSUFFICIENT_SECURITY           (71),
    INTERNAL_ERROR                  (80),
    INAPPROPRIATE_FALLBACK          (86), // could also be sent for SSLv3
    USER_CANCELED                   (90),
    NO_RENEGOTIATION                (100),

    // Alerts for client hello extensions
    MISSING_EXTENSION               (109),
    UNSUPPORTED_EXTENSION           (110),
    CERTIFICATE_UNOBTAINABLE        (111),
    UNRECOGNIZED_NAME               (112),
    BAD_CERTIFICATE_STATUS_RESPONSE (113),
    BAD_CERTIFICATE_HASH_VALUE      (114),
    NO_APPLICATION_PROTOCOL         (120);

    private int id;

    private SSLAlertDescription(int id) {
        this.id = id;
    }

    public int getID() {
        return id;
    }

    public static SSLAlertDescription valueOf(int id) {
        for (SSLAlertDescription description : SSLAlertDescription.class.getEnumConstants()) {
            if (description.id == id) return description;
        }
        return null;
    }
}
