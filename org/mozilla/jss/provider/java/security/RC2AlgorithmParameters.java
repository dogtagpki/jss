/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.java.security;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.RC2ParameterSpec;

/**
 * This class is only intended to be used to implement
 * CipherSpi.getAlgorithmParameters().
 */
public class RC2AlgorithmParameters extends AlgorithmParametersSpi {

    private RC2ParameterSpec RC2ParamSpec;

    public void engineInit(AlgorithmParameterSpec paramSpec) {
        RC2ParamSpec = (RC2ParameterSpec) paramSpec;
    }

    public <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> clazz)
            throws InvalidParameterSpecException
    {
        if( clazz != null && !clazz.isInstance(RC2ParamSpec) ) {
            Class<?> paramSpecClass = RC2ParamSpec.getClass();
            throw new InvalidParameterSpecException(
                "RC2 getParameterSpec has class " + paramSpecClass.getName());
        }
        return clazz.cast(RC2ParamSpec);
    }

    public void engineInit(byte[] params) throws IOException {
        throw new IOException("engineInit(byte[]) not supported");
    }

    public void engineInit(byte[] params, String format) throws IOException {
        throw new IOException("engineInit(byte[],String) not supported");
    }

    public byte[] engineGetEncoded() throws IOException {
        throw new IOException("encoding RC2AlgorithmParameters not supported");
    }

    public byte[] engineGetEncoded(String format) throws IOException {
        throw new IOException("encoding RC2AlgorithmParameters not supported");
    }

    public String engineToString() {
        String str = new String("Mozilla-JSS RC2AlgorithmParameters " +  getClass().getName());
        return str;
    }
}
