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
package org.mozilla.jss.netscape.security.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.StringTokenizer;
import java.util.Vector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Utils {

    private static final Logger logger = LoggerFactory.getLogger(Utils.class);
    /**
     * Checks if this is NT.
     */
    public static boolean isNT() {
        return File.separator.equals("\\");
    }

    public static boolean isUnix() {
        return File.separator.equals("/");
    }

    public static boolean exec(String cmd) {
        try {
            String cmds[] = null;
            if (isNT()) {
                // NT
                cmds = new String[3];
                cmds[0] = "cmd";
                cmds[1] = "/c";
                cmds[2] = cmd;
            } else {
                // UNIX
                cmds = new String[3];
                cmds[0] = "/bin/sh";
                cmds[1] = "-c";
                cmds[2] = cmd;
            }
            Process process = Runtime.getRuntime().exec(cmds);
            process.waitFor();

            if (process.exitValue() == 0) {
                /**
                 * pOut = new BufferedReader(
                 * new InputStreamReader(process.getInputStream()));
                 * while ((l = pOut.readLine()) != null) {
                 * System.out.println(l);
                 * }
                 **/
                return true;
            } else {
                /**
                 * pOut = new BufferedReader(
                 * new InputStreamReader(process.getErrorStream()));
                 * l = null;
                 * while ((l = pOut.readLine()) != null) {
                 * System.out.println(l);
                 * }
                 **/
                return false;
            }
        } catch (IOException e) {
            logger.error("The command canot be executed: " + cmd, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return false;
    }

    public static String readFromStream(InputStream inputStream) throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(inputStream));
            String line = null;
            while ((line = br.readLine()) != null) {
                sb.append(line + System.getProperty("line.separator"));
            }
        } finally {
            br.close();
        }
        return sb.toString().trim();
    }

    public static void writeToStream(OutputStream outputStream, String input) throws IOException {
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(outputStream));
        writer.write(input);
        writer.flush();
        writer.close();
    }

    /**
     * Utility method to execute system commands
     *
     * @param cmd The command to be executed and its arguments
     * @param input The stdin input to be passed to the cmd
     * @return stdout or stderr of the command executed
     * @throws IOException
     * @throws InterruptedException
     */
    public static String exec(String[] cmd, String input) throws IOException, InterruptedException {

        ProcessBuilder pb = new ProcessBuilder(cmd);

        Process p = pb.start();

        if (input != null) {
            writeToStream(p.getOutputStream(), input);
        }

        p.waitFor();

        String output;
        if (p.exitValue() == 0) {
            output = readFromStream(p.getInputStream());
        } else {
            output = readFromStream(p.getErrorStream());
        }
        p.destroy();

        return output;
    }



    public static String SpecialURLDecode(String s) {
        if (s == null)
            return null;
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());

        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);

            if (c == '+') {
                out.write(' ');
            } else if (c == '#') {
                int c1 = Character.digit(s.charAt(++i), 16);
                int c2 = Character.digit(s.charAt(++i), 16);

                out.write((char) (c1 * 16 + c2));
            } else {
                out.write(c);
            }
        } // end for
        return out.toString();
    }

    public static byte[] SpecialDecode(String s) {
        if (s == null)
            return null;
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());

        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);

            if (c == '+') {
                out.write(' ');
            } else if (c == '#') {
                int c1 = Character.digit(s.charAt(++i), 16);
                int c2 = Character.digit(s.charAt(++i), 16);

                out.write((char) (c1 * 16 + c2));
            } else {
                out.write(c);
            }
        } // end for
        return out.toByteArray();
    }

    public static String SpecialEncode(byte data[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            sb.append("%");
            if ((data[i] & 0xff) < 16) {
                sb.append("0");
            }
            sb.append(Integer.toHexString((data[i] & 0xff)));
        }
        return sb.toString().toUpperCase();
    }

    public static String HexEncode(byte data[]) {
        StringBuffer sb = new StringBuffer();
        if (data != null) {
            for (int i = 0; i < data.length; i++) {
                if ((data[i] & 0xff) < 16) {
                    sb.append("0");
                }
                sb.append(Integer.toHexString((data[i] & 0xff)));
            }
        }
        return sb.toString();
    }

    public static void checkHost(String hostname) throws UnknownHostException {
        InetAddress.getByName(hostname);
    }

    public static void copy(String orig, String dest) throws Exception {
        try (BufferedReader in = new BufferedReader(new FileReader(orig));
                PrintWriter out = new PrintWriter(
                    new BufferedWriter(new FileWriter(dest)))) {
            String line = "";
            while (in.ready()) {
                line = in.readLine();
                if (line != null)
                    out.println(line);
            }
        }
    }

    public static void copyStream(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[4096];
        int len;

        while ((len = in.read(buf)) != -1) {
            out.write(buf, 0, len);
        }
    }

    public static void copyStream(BufferedReader in, OutputStreamWriter out) throws IOException {
        char[] buf = new char[4096];
        int len;

        while ((len = in.read(buf)) != -1) {
            out.write(buf, 0, len);
        }
    }

    /// Sorts an array of Strings.
    // Java currently has no general sort function.  Sorting Strings is
    // common enough that it's worth making a special case.
    public static void sortStrings(String[] strings) {
        // Just does a bubblesort.
        for (int i = 0; i < strings.length - 1; ++i) {
            for (int j = i + 1; j < strings.length; ++j) {
                if (strings[i].compareTo(strings[j]) > 0) {
                    String t = strings[i];

                    strings[i] = strings[j];
                    strings[j] = t;
                }
            }
        }
    }

    /// Returns a date string formatted in Unix ls style - if it's within
    // six months of now, Mmm dd hh:ss, else Mmm dd  yyyy.
    public static String lsDateStr(Date date) {
        long dateTime = date.getTime();

        if (dateTime == -1L)
            return "------------";
        long nowTime = System.currentTimeMillis();
        SimpleDateFormat formatter = new SimpleDateFormat();

        if (Math.abs(nowTime - dateTime) < 183L * 24L * 60L * 60L * 1000L)
            formatter.applyPattern("MMM dd hh:ss");
        else
            formatter.applyPattern("MMM dd yyyy");
        return formatter.format(date);
    }

    /**
     * compares contents two byte arrays returning true if exactly same.
     */
    static public boolean byteArraysAreEqual(byte[] a, byte[] b) {
        if (a.length != b.length)
            return false;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i])
                return false;
        }
        return true;
    }

    /**
     * strips out double quotes around String parameter
     *
     * @param s the string potentially bracketed with double quotes
     * @return string stripped of surrounding double quotes
     */
    public static String stripQuotes(String s) {
        if (s == null) {
            return s;
        }

        if ((s.startsWith("\"")) && (s.endsWith("\""))) {
            return (s.substring(1, (s.length() - 1)));
        }

        return s;
    }

    /**
     * returns an array of strings from a vector of Strings
     * there'll be trouble if the Vector contains something other
     * than just Strings
     */
    public static String[] getStringArrayFromVector(Vector<String> v) {
        String s[] = new String[v.size()];

        v.copyInto(s);
        return s;
    }

    /**
     * Converts a byte array into a Base-64 encoded string.
     * If the chunked option is true, the output will be split into
     * multiple lines. Otherwise, the output will be a single line.
     *
     * @param bytes byte array
     * @param chunked generate chunked output
     * @return base-64 encoded data
     */
    public static String base64encode(byte[] bytes, boolean chunked) {
        if (chunked) {
            return base64encodeMultiLine(bytes);
        } else {
            return base64encodeSingleLine(bytes);
        }
    }

    /**
     * Converts a byte array into a multi-line Base-64 encoded string.
     * Each line is at most 64-character long and terminated with CRLF.
     *
     * @param bytes byte array
     * @return base-64 encoded data
     */
    public static String base64encodeMultiLine(byte[] bytes) {
        // When switching from apache-commons-codec to the standard library,
        // the standard library does not include a final line separator at
        // the end of the encoded data. This results in malformed CSRs.
        return Base64.getMimeEncoder().encodeToString(bytes) + "\r\n";
    }


    /**
     * Converts a byte array into a single-line Base-64 encoded string.
     * The line is not terminated with CRLF.
     *
     * @param bytes byte array
     * @return base-64 encoded data
     */
    public static String base64encodeSingleLine(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Converts a Base-64 encoded string into a byte array.
     *
     * @param string base-64 encoded data
     * @return byte array
     */
    public static byte[] base64decode(String string) {
        try {
            // Java is particular about its base64. We already used the MIME
            // decoder as it was most flexible about whitespace. However, it
            // doesn't understand URL-encoded Base64 (using '-' instead of
            // '+' and '_' instead of '/'). So, detect those characters and
            // pass it to the correct decoder.
            if (string.contains("_") || string.contains("-")) {
                return Base64.getUrlDecoder().decode(string);
            } else {
                return Base64.getMimeDecoder().decode(string);
            }
        } catch (IllegalArgumentException iae) {
            return new byte[0];
        }
    }

    /**
     * Normalize B64 input String
     *
     * @param string base-64 string
     * @return normalized string
     */
    public static String normalizeString(String string) {
        return normalizeString(string, false);
    }

    /**
     * Normalize B64 input String
     *
     * @param string base-64 string
     * @param keepSpace a boolean variable to control whether to keep spaces or not
     * @return normalized string
     */
    public static String normalizeString(String string, Boolean keepSpace) {
        if (string == null) {
            return string;
        }

        StringBuffer sb = new StringBuffer();
        StringTokenizer st = null;
        if (keepSpace)
            st = new StringTokenizer(string, "\r\n");
        else
            st = new StringTokenizer(string, "\r\n ");

        while (st.hasMoreTokens()) {
            String nextLine = st.nextToken();
            nextLine = nextLine.trim();
            sb.append(nextLine);
        }
        return sb.toString();
    }

}
