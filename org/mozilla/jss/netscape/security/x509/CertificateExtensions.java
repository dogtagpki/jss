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
package org.mozilla.jss.netscape.security.x509;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;

/**
 * This class defines the Extensions attribute for the Certificate.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.11
 * @see CertAttrSet
 */
public class CertificateExtensions extends Vector<Extension>
        implements CertAttrSet, Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -7172635300185788849L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions";
    /**
     * name
     */
    public static final String NAME = "extensions";

    private Hashtable<String, Extension> map;

    // Parse the encoded extension
    public void parseExtension(Extension ext) throws IOException {
        try {
            @SuppressWarnings("unchecked")
            Class<CertAttrSet> extClass = (Class<CertAttrSet>) OIDMap.getClass(ext.getExtensionId());
            if (extClass == null) { // Unsupported extension
                map.put(ext.getExtensionId().toString(), ext);
                addElement(ext);
                return;
            }
            Class<?>[] params = { Boolean.class, Object.class };
            Constructor<CertAttrSet> cons = extClass.getConstructor(params);

            byte[] extData = ext.getExtensionValue();
            int extLen = extData.length;
            Object value = Array.newInstance(byte.class, extLen);

            for (int i = 0; i < extLen; i++) {
                Array.setByte(value, i, extData[i]);
            }
            Object[] passed = new Object[] { Boolean.valueOf(ext.isCritical()),
                    value };
            CertAttrSet certExt = cons.newInstance(passed);
            if (certExt != null && certExt.getName() != null) {
                map.put(certExt.getName(), (Extension) certExt);
                addElement((Extension) certExt);
            }

        } catch (NoSuchMethodException e) {
            throw new IOException(e);

        } catch (InvocationTargetException e) {
            Throwable t = e.getTargetException();
            if (t instanceof IOException) {
                throw (IOException)t;
            }
            throw new IOException(t);

        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * Default constructor for the certificate attribute.
     */
    public CertificateExtensions() {
        map = new Hashtable<String, Extension>();
    }

    /**
     * Create the object, decoding the values from the passed DER stream.
     *
     * @param in the DerInputStream to read the Extension from.
     * @exception IOException on decoding errors.
     */
    public CertificateExtensions(DerInputStream in)
            throws IOException {

        map = new Hashtable<String, Extension>();
        DerValue[] exts = in.getSequence(5);

        for (int i = 0; i < exts.length; i++) {
            Extension ext = new Extension(exts[i]);
            parseExtension(ext);
        }
    }

    /**
     * Decode the extensions from the InputStream.
     *
     * @param in the InputStream to unmarshal the contents from.
     * @exception IOException on decoding or validity errors.
     */
    public void decode(InputStream in) throws IOException {
        DerValue val = new DerValue(in);
        DerInputStream str = val.toDerInputStream();

        map = new Hashtable<String, Extension>();
        DerValue[] exts = str.getSequence(5);

        for (int i = 0; i < exts.length; i++) {
            Extension ext = new Extension(exts[i]);
            parseExtension(ext);
        }
    }

    /**
     * Decode the extensions from the InputStream.
     *
     * @param in the InputStream to unmarshal the contents from.
     * @exception IOException on decoding or validity errors.
     */
    public void decodeEx(InputStream in) throws IOException {
        DerValue val = new DerValue(in);
        DerInputStream str = null;
        if (val.isConstructed() && val.isContextSpecific((byte) 3)) {
            str = val.data;
        } else {
            str = val.toDerInputStream();
        }

        map = new Hashtable<String, Extension>();
        DerValue[] exts = str.getSequence(5);

        for (int i = 0; i < exts.length; i++) {
            Extension ext = new Extension(exts[i]);
            parseExtension(ext);
        }
    }

    private void writeObject(ObjectOutputStream stream) throws CertificateException, IOException {
        encode(stream);
    }

    private void readObject(ObjectInputStream stream) throws CertificateException, IOException {
        decodeEx(stream);
    }

    /**
     * Encode the extensions in DER form to the stream.
     *
     * @param out the DerOutputStream to marshal the contents to.
     * @exception CertificateException on encoding errors.
     * @exception IOException on errors.
     */
    public void encode(OutputStream out)
            throws CertificateException, IOException {
        try (DerOutputStream tmp = new DerOutputStream()) {
            DerOutputStream extOut = new DerOutputStream();
            for (int i = 0; i < size(); i++) {
                Object thisOne = elementAt(i);
                if (thisOne instanceof CertAttrSet)
                    ((CertAttrSet) thisOne).encode(extOut);
                else if (thisOne instanceof Extension)
                    ((Extension) thisOne).encode(extOut);
                else
                    throw new CertificateException("Invalid extension object");
            }

            DerOutputStream seq = new DerOutputStream();
            seq.write(DerValue.tag_Sequence, extOut);

            tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 3),
                    seq);

            out.write(tmp.toByteArray());
        }
    }

    /**
     * Set the attribute value.
     *
     * @param name the extension name used in the cache.
     * @param obj the object to set.
     * @exception IOException if the object could not be cached.
     */
    public void set(String name, Object obj) throws IOException {
        map.put(name, (Extension) obj);
        addElement((Extension) obj);
    }

    /**
     * Get the attribute value.
     *
     * @param name the extension name used in the lookup.
     * @exception IOException if named extension is not found.
     */
    public Object get(String name) throws IOException {
        Object obj = map.get(name);
        if (obj == null) {
            throw new IOException("No extension found with name " + name);
        }
        return (obj);
    }

    /**
     * Delete the attribute value.
     *
     * @param name the extension name used in the lookup.
     * @exception IOException if named extension is not found.
     */
    public void delete(String name) throws IOException {
        Object obj = map.get(name);
        if (obj == null) {
            throw new IOException("No extension found with name " + name);
        }
        map.remove(name);
        removeElement(obj);
    }

    public Enumeration<String> getNames() {
        return map.keys();
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<Extension> getAttributes() {
        return (map.elements());
    }

    public Enumeration<String> getAttributeNames() {
        return (map.keys());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((map == null) ? 0 : map.hashCode());
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
        CertificateExtensions other = (CertificateExtensions) obj;
        if (map == null) {
            if (other.map != null)
                return false;
        } else if (!map.equals(other.map))
            return false;
        return true;
    }

}
