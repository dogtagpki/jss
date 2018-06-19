// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.mozilla.jss.netscape.security.provider;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.interfaces.DSAParams;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.mozilla.jss.netscape.security.util.BigInt;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.x509.AlgIdDSA;
import org.mozilla.jss.netscape.security.x509.X509Key;

/**
 * An X.509 public key for the Digital Signature Algorithm.
 *
 * @author Benjamin Renaud
 *
 * @version 1.52, 97/12/10
 *
 * @see DSAPrivateKey
 * @see AlgIdDSA
 * @see DSA
 */

public final class DSAPublicKey extends X509Key
        implements java.security.interfaces.DSAPublicKey, Serializable {

    /** use serialVersionUID from JDK 1.1. for interoperability */
    private static final long serialVersionUID = -2994193307391104133L;

    /* the public key */
    private BigInteger y;

    /*
     * Keep this constructor for backwards compatibility with JDK1.1.
     */
    public DSAPublicKey() {
    }

    /**
     * Make a DSA public key out of a public key and three parameters.
     */
    public DSAPublicKey(BigInteger y, BigInteger p, BigInteger q,
            BigInteger g)
            throws InvalidKeyException {
        this.y = y;
        algid = new AlgIdDSA(p, q, g);

        try {
            key = new DerValue(DerValue.tag_Integer,
                    y.toByteArray()).toByteArray();
            encode();
        } catch (IOException e) {
            throw new InvalidKeyException("could not DER encode y: " +
                      e.getMessage());
        }
    }

    /**
     * Make a DSA public key from its DER encoding (X.509).
     */
    public DSAPublicKey(byte[] encoded) throws InvalidKeyException {
        decode(encoded);
    }

    /**
     * Returns the DSA parameters associated with this key, or null if the
     * parameters could not be parsed.
     */
    public DSAParams getParams() {
        try {
            if (algid instanceof DSAParams) {
                return (DSAParams) algid;
            } else {
                DSAParameterSpec paramSpec;
                AlgorithmParameters algParams = algid.getParameters();
                if (algParams == null) {
                    return null;
                }
                paramSpec = algParams.getParameterSpec
                        (DSAParameterSpec.class);
                return paramSpec;
            }
        } catch (InvalidParameterSpecException e) {
            return null;
        }
    }

    /**
     * Get the raw public value, y, without the parameters.
     *
     */
    public BigInteger getY() {
        return y;
    }

    public String toString() {
        return "Sun DSA Public Key\n    Parameters:" + algid
                + "\n  y:\n" + (new BigInt(y)).toString() + "\n";
    }

    protected void parseKeyBits() throws InvalidKeyException {
        try {
            DerInputStream in = new DerInputStream(key);
            y = in.getInteger().toBigInteger();
        } catch (IOException e) {
            throw new InvalidKeyException("Invalid key: y value\n" +
                      e.getMessage());
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((y == null) ? 0 : y.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        DSAPublicKey other = (DSAPublicKey) obj;
        if (y == null) {
            if (other.y != null)
                return false;
        } else if (!y.equals(other.y))
            return false;
        return true;
    }

}
