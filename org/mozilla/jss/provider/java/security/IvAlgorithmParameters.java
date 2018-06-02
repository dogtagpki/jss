/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.java.security;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

/**
 * This class is only intended to be used to implement
 * CipherSpi.getAlgorithmParameters().
 */
public class IvAlgorithmParameters extends AlgorithmParametersSpi {

    private IvParameterSpec ivParamSpec;

    public void engineInit(AlgorithmParameterSpec paramSpec) {
        ivParamSpec = (IvParameterSpec) paramSpec;
    }

    public AlgorithmParameterSpec engineGetParameterSpec(Class clazz)
            throws InvalidParameterSpecException
    {
        if( clazz != null && !(clazz.isInstance(ivParamSpec)) ) {
            Class paramSpecClass = ivParamSpec.getClass();
            throw new InvalidParameterSpecException(
                "Mozilla-JSS IvParameter spec class error"
                    + paramSpecClass.getName());
        }
        return ivParamSpec;
    }

    public void engineInit(byte[] params) throws IOException {
        throw new IOException("engineInit(byte[]) not supported");
    }

    public void engineInit(byte[] params, String format) throws IOException {
        throw new IOException("engineInit(byte[],String) not supported");
    }

    public byte[] engineGetEncoded() throws IOException {
        throw new IOException("encoding IvAlgorithmParameters not supported");
    }

    public byte[] engineGetEncoded(String format) throws IOException {
        throw new IOException("encoding IvAlgorithmParameters not supported");
    }

    public String engineToString() {
        throw new RuntimeException("engineToString() not supported");
        // return getClass().getName();
    }
}
