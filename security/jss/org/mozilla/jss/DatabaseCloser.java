/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss;

/**
 * A class for closing databases. Since closing the databases is
 * very dangerous and breaks the JSS model, it may only be done from  
 * special applications. This class should be subclasses by
 * authorized subclasses.  It cannot be instantiated itself.
 */
public abstract class DatabaseCloser {

    private static final String authorizedClosers[] =
        {   "org.mozilla.certsetup.apps.CertSetup$DatabaseCloser",
            "org.mozilla.jss.CloseDBs"                                  };

    /**
     * Creates a new DatabaseCloser.  This should only be called
     * from an authorized subclass.  This class cannot itself be
     * instantiated.
     *
     * @throws Exception If the instantiation is not a valid subclass.
     */
    public DatabaseCloser() throws Exception {
        Class clazz = this.getClass();
        String name = clazz.getName();
        boolean approved = false;
        for(int i=0; i < authorizedClosers.length; i++) {
            if( name.equals( authorizedClosers[i] ) ) {
                approved = true;
                break;
            }
        }
        if(!approved) {
            throw new Exception();
        }
    }

    /**
     * Closes the certificate and key databases.  This is extremely
     * dangerous.
     */
    protected native void closeDatabases();
}
