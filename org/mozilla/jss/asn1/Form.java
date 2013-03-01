/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

/**
 * An enumerated type representing the forms of an ASN.1 value.
 * The possibilities are PRIMITIVE and CONSTRUCTED.
 */
public class Form {
    private String name;

    private Form() { }

    private Form(String name) {
        this.name = name;
    }

    public static final Form PRIMITIVE = new Form("PRIMITIVE");
    public static final Form CONSTRUCTED = new Form("CONSTRUCTED");

    public String toString() {
        return name;
    }
}
