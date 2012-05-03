/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
// 
// 
//
// $Id$


package org.mozilla.jss.ssl;

import java.io.*;
import java.util.*;



class PrintOutputStreamWriter 
    extends java.io.OutputStreamWriter
{

    public PrintOutputStreamWriter(OutputStream out)
    {
    	super(out);
    }

    public void print(String x) 
	throws  java.io.IOException
    {
    	write(x, 0, x.length());
    }

    public void println(String x)
	throws  java.io.IOException
    {
//	String line = new String(x + "\n");
	String line = x + "\n";
	write(line, 0, line.length());
	flush();
    }

}
