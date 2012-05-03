/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;

/**
 * A command-line utility for generating PQG parameters for DSA
 * Key operations. Can be used for testing.
 * Takes the keysize as the sole argument.
 */
public class PQGGen {
    public static void main(String args[]) {
        int size;
        PQGParams pqg;

      try {

        if(args.length != 1) {
            throw new Exception("Usage: java PQGGen <keysize>");
        }

        size = Integer.parseInt(args[0]);

        System.out.println("Generating PQG parameters for "+size+
                            "-bit keypairs. This could take hours...");

        CryptoManager.initialize(".");

        pqg = PQGParams.generate(size);

        System.out.println("Generated PQG Parameters.");
        System.out.println("Verifying PQG Parameters. "+
                            "This could take a few minutes...");
        if( ! pqg.paramsAreValid() ) {
            throw new Exception("ERROR: Generated parameters are invalid.");
        }

        System.out.println("Parameters are valid!");
        System.out.println("P: "+pqg.getP());
        System.out.println("Q: "+pqg.getQ());
        System.out.println("G: "+pqg.getG());
        System.out.println("H: "+pqg.getH());
        System.out.println("seed: "+pqg.getSeed());
        System.out.println("counter: "+pqg.getCounter());

      } catch(NumberFormatException e) {
          System.err.println("Invalid key size: "+e);
      } catch(PQGParamGenException e) {
          System.err.println(e);
      } catch(java.security.InvalidParameterException e) {
          System.err.println("Invalid key size: "+e);
      } catch(Exception e) {
          System.err.println(e);
      }
    }
}
