/* EEL4915 - Develop demonstration FFX encryption and decryption for ADS-B
   2015 May 16, Michael Vose
   Specific FF1 implementation of the FFX algorithm. Method arguments are not based 
   on parameter set A2. Feistel method Left(1) is used to increase the imbalance factor. 
   Other parameters are described in program comments. Refer to these documents for
   additional information:
   - The FFX Mode of Operation for Format-Preserving Encryption, 
     http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec.pdf
   - Addendum to, "The FFX Mode of Operation for Format-Preserving Encryption,"
     http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf
   - NIST Special Publication 800-38G,
     http://csrc.nist.gov/publications/drafts/800-38g/sp800_38g_draft.pdf
   - ANSI Draft Standard x9.124, https://x9.org/ (member companies only)
   - US Patent 7864952-B2, <-- This is a granted patent that covers portions of FPE.
     Data processing systems with format-preserving encryption and decryption engines,
     http://www.google.com/patents/US7864952
*/
import java.lang.IllegalArgumentException;
import java.lang.Math;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.BitSet;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
//import javax.xml.bind.DatatypeConverter; // not natively supported on Android

/* This implements FF1 with parameters favorable to processing an ADS-B extended 
   squitter message. This is not parameter set A2. Method=1 is used to increase the 
   imbalance factor. For a detailed discussion of unbalanced Feistel networks, see
   https://www.schneier.com/paper-unbalanced-feistel.pdf
   This is an academic implementation intended to follow the FFX draft specification  
   while using Java and remaining compatible with Android. It is not optimized.
   The terminology, variable names, and methods employed here follow the original 
   ffx-spec.pdf document rather than the later variations and proposals.
*/
public class FF1LS80 {
   //         | | '-> S80 refers to the custom 80-bit split()
   //         | '---> L   refers to the use of Feistel method Left
   //         '-----> FF1 refers to the algorithm type within the FFX family
   
   // Constants.. hexArray is used by bytesToHex()
   final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
   
   // Class Variables.. (FF1 Parameter Set)
   int      radix;                  // size of the symbol set - only {0,1} is supported
   int      n = 0;                  // message size in bits, a positive multiple of 8
   
   int[]    Lengths = new int[16];  // Lengths array - valid message sizes in bits
                                    // ..16 elements is arbitrary, change as needed.
   int      Lidx = -1;              // watermark index to the Lengths array
   
   byte[]   keyHex  = new byte[16]; // A crypto key in byte array form
   SecretKeySpec Keys0;             // packaged AES key
   
   //       Tweaks                  // supplied only at run-time
   
   int      addition;               // Operation mode: bitwise=0 vs blockwise=1,
                                    // ..(this class only implements bitwise.)

   int      method;                 // Feistel method: 1 for Left (unbalanced)
                                    //                 2 for Right (balanced)
                                    // ..(this class only implements method=1.)

   int      imbalance;              // split(n) sets the fundamental imbalance
   
   int      remainder;              // n-split(n) is the rest of the message
   
   int      rounds;                 // rnds(n) sets minimum rounds of encryption
   
   //       F                       // only AES(128) mode-CBC is demonstrated here
   
   /* Explicit Constructor
      Expects an AES(128) key supplied as 32 hexidecimal digits.
      Invokes hexToBytes() and SecretKeySpec().
      Populates a portion of the custom FF1 parameter set.
      addValidSize() must now also be called at least once before Encrypt() or Decrypt().
   */
    FF1LS80(String keyStr) {
      radix      = 2;       // it's a binary symbol set {0,1}
                            // this is strictly documentation - only bitwise is supported
      keyHex     = hexToBytes(keyStr);
      Keys0      = new SecretKeySpec(keyHex, "AES"); // Per spec Keys s/b array but Cipher 
                                                     // ..demands a specfic container.
      addition   = 0;       // bitwise operation in radix=2 means XOR for both enc/dec
      method     = 1;       // this class' purpose is to demo unbalanced Feistel for ADS-B
    }

   /*-Supporting Methods-----------------------------------------------------*/
   
   /* addValidSize() prepares FF1 to accept a given message length. 
      Invokes setCurrentSize().
      Populates a portion of the custom FF1 parameter set.
   */
   public int addValidSize(int n) {
      boolean rc;                     // prep result variable for checkLengths()
      rc = checkLengths(n);           // in this case, we want a 1 return = no match
      if (rc) {                       // this is a new n
         if (n%8==0 && n>=88) {       // check that n is a multiple of 8 and in range
            Lidx = Lidx + 1;          // first element is index 0, (-1+1=0.)
            Lengths[Lidx] = n;        // only one size is needed for extended squitter
            setCurrentSize(n);        // update all the parameters dependent on n
            return 0;                 // normal return
         }
         else {
            System.out.println("FF1LS80.addValidSize: Error - message size ("+n+") is not valid.");
            return 2; // either n is not a multiple of 8 or n is less than 88
         }
      }
      else {
         System.out.println("FF1LS80.addValidSize: Warning - message size ("+n+") is already added.");
         return 1; // duplicate size ignored
      }
   }

   /* validateInput() does one of three things:
      1.) Nothing. The message size is the same. No changes are needed.
      2.) Throw IllegalArgumentException to begin termination of the process.
      3.) The class is adjusted to process a different valid message size.
      It is invoked by Encrypt(), and Decrypt().
   */
   private void validateInput(int n) throws IllegalArgumentException {
      boolean rc;                     // prep result variable in case we need checkLengths()
      if (n != this.n) {              // Is the input a different size this time?
         rc = checkLengths(n);        // ..Yes, make sure this is a known n.
         if (rc) {                    // true return means no match found
            System.out.println("FF1LS80.validateInput: Error - unanticipated message size ("+n+").");
            throw new IllegalArgumentException(); // every n must be known in advance
         }
         else {                       // this is a known n (match found)
            setCurrentSize(n);        // Update all the parameters dependent on n
         }
      }
   }
   
   /* checkLengths() is a simple search of the valid lengths array for a given value.
      It is invoked by addValidSize(), Encrypt(), and Decrypt().
      Zero return means a match is found.
      Return value 1 means no match is found.
   */
   private boolean checkLengths(int n) {
      for (int i=0; i<Lidx+1; i=i+1) {
         if (Lengths[i]==n) {         // check if this n is already known
             return false;            // yes, this n is known as a valid length
         }                            // no, check the next length
      }
      return true;                    // no match found
   }

   /* setCurrentSize() updates all the FF1 parameters dependent on n. 
      Invokes split(), rnds().
   */
   private void setCurrentSize(int n) {
      this.n    = n;            // set the class n value to the local n value
      imbalance = split(n);
      remainder = n-imbalance;  // term not part of spec - compliment of imbalance, mod n
      rounds    = rnds(n);
      return;
   }
   
   /* split(n) function required by FFX specification...
      Argument-n must be a positive multiple of 8. The result is a number between 1 and n/2 
      (inclusive) which is only dependent upon n, (e.g. different n values will yield 
      different results.) The specification does not require a split of n/2, (as it does 
      with the balanced parameter set A2.) I have selected n-80 to unbalance the split 
      without creating remainders that are not byte-aligned.
   */
   private int split(int n) {
      int nSplit = n-80;
      return nSplit;
   }

   /* rnds(n) function required by FFX specification...
      rnds(n) calls split(n), so argument-n must be a positive multiple of 8. The 
      specification dictates rnds(n)>=4n/split(n). If fractional, the result is rounded 
      up to the next integer. The Addendum proposes a compromise to use a lesser and common 
      number of rounds; the count of which is not dependent on the message size. The 
      original method is employed here and consideration should be given to updating this 
      method as FFX matures into a true standard.
   */
   private int rnds(int n) {
      int nRounds = (int) Math.ceil((n*4.0)/split(n)); 
      return nRounds;
   }

   /* hexToBytes() - equivalent to javax.xml.bind.DataTypeConverter.parseHexBinary()
      ...I don't want to distribute .jar files under Android
      As documented at,
      http://stackoverflow.com/questions/18714616/convert-hex-string-to-byte
   */
   public static byte[] hexToBytes(String s) {
       int len = s.length();
       byte[] data = new byte[len / 2];
       for (int i = 0; i < len; i += 2) {
           data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                + Character.digit(s.charAt(i+1), 16));
       }
       return data;
   }

   /* bytesToHex() - equivalent to javax.xml.bind.DataTypeConverter.printHexBinary()
      ...I don't want to distribute .jar files under Android
      As documented at,
      http://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
   */
   public static String bytesToHex(byte[] bytes) {
       char[] hexChars = new char[bytes.length * 2];
       for ( int j = 0; j < bytes.length; j++ ) {
           int v = bytes[j] & 0xFF;
           hexChars[j * 2] = hexArray[v >>> 4];
           hexChars[j * 2 + 1] = hexArray[v & 0x0F];
       }
       return new String(hexChars);
   }

   /*-Encryption-------------------------------------------------------------*/
   
   /* Encrypt() paraphrased from the draft spec... 
         where X is the plaintext message
         where F is the underlying encryption algorithm (AES)

      Encrypt(Key, Tweak, X) {
         if (method=1) and (Key, Tweak, symbols in X, and X length are all valid)
            // (all but length are given or assumed)
            for i = 0 to rounds-1 {
               A = X[from bit 1 to bit split(n)]
               B = X[from bit split(n)+1 to bit n]
               C = A XOR F(n, T, i, B)
               X = B concat C
            }
            return X
         end if
      }
      In this implementation, the key is set at instantiation. Just Tweak and X are passed.
   */
   public byte[] Encrypt(byte[] Tweak, byte[] Xi) throws IllegalArgumentException {
      try {
         validateInput(Xi.length*8);          // make sure this n is known
      }
      catch (IllegalArgumentException e) {
         throw new IllegalArgumentException(); // all lengths must be known in advance
      }
      // BitSets round up to multiples of 64 bits
      BitSet X  = new BitSet(n);              // the plaintext
      BitSet A  = new BitSet(imbalance);      // first portion of plaintext - becomes encrypted
      int Asize = (int) Math.ceil(imbalance/8.0); // How many bytes will it require? Round up.
      byte[] ACipher  = new byte[Asize];      // ..as a byte array
      BitSet B  = new BitSet(remainder);      // remainder of plaintext - persists one round
      int Bsize = (int) Math.ceil(remainder/8.0); // How many bytes will it require? Round up.
      byte[] BCipher  = new byte[Bsize];      // ..as a byte array
      byte[] C1Cipher = new byte[Bsize];      // interim enc factor from AES
      BitSet Z1 = new BitSet(remainder);      // interim enc factor from AES (as a BitSet)
      BitSet Z2 = new BitSet(imbalance);      // interim enc factor pending XOR with A 
      BitSet C  = new BitSet(imbalance);      // interim enc (C and A are the same size)
      byte[] C2Cipher = new byte[Asize];      // ..result for this FF1 round
      try {
         // For AES-CBC from Cipher, PKCS5 is processed internally as PKCS7.
         Cipher AESCBC = Cipher.getInstance("AES/CBC/PKCS5Padding"); // explicit to ensure CBC mode
         AESCBC.init(Cipher.ENCRYPT_MODE, Keys0, new IvParameterSpec(Tweak));
         // Ready to begin FF1 rounds
         for(int i=0; i<rounds; i=i+1) {
            X = BitSet.valueOf(Xi);           // byte[] to BitSet
            A = X.get(0, imbalance);          // fromIndex is inclusive and toIndex is exclusive
            if (A.length() < (imbalance-8)) { // A.length() is the highest set index +1
               A.set(imbalance-8);            // BitSet is short - set bit in last byte
               ACipher = A.toByteArray();     // Convert to byte array and then use
               ACipher[Asize-1] ^= 0x01;      // ..bitwise xor and clear() to unset
               A.clear(imbalance-8);          // ..the forced bit in both locations
            }
            else
               ACipher = A.toByteArray();     // enough bits - use as is
            B = X.get(imbalance, n);
            if (B.length() < (remainder-8)) { // B.length() is the highest set index +1
               B.set(remainder-8);            // BitSet is short - set bit in last byte
               BCipher = B.toByteArray();     // Convert to byte array and then use
               BCipher[Bsize-1] ^= 0x01;      // ..bitwise xor and clear() to unset
               B.clear(remainder-8);          // ..the forced bit in both locations
            }
            else
               BCipher = B.toByteArray();     // enough bits - use as is
            // This builds an enc factor - it does not really encrypt the data
            C1Cipher = AESCBC.doFinal(BCipher);
            Z1 = BitSet.valueOf(C1Cipher);  
            Z2 = Z1.get(0, imbalance);        // select the relevant bits from the factor
            C = (BitSet) A.clone();           // resync variable names to the spec
            // XOR encrypts this portion using the enc factor
            C.xor(Z2);
            if (C.length() < (imbalance-8)) { // C.length() is the highest set index +1
               C.set(imbalance-8);            // BitSet is short - set bit in last byte
               C2Cipher = C.toByteArray();    // Convert to byte array and then use
               C2Cipher[Asize-1] ^= 0x01;     // ..bitwise xor and clear() to unset
               C.clear(imbalance-8);          // ..the forced bit in both locations
            }
            else
               C2Cipher = C.toByteArray();    // enough bits - use as is
            // Reassemble the partially encrypted message from B || C
            System.arraycopy(BCipher, 0, Xi, 0, Bsize);
            System.arraycopy(C2Cipher, 0, Xi, BCipher.length, C2Cipher.length);
            // Xi is ready for the next FF1 round
         }
         // Xi is fully encrypted
      }
      catch (NoSuchAlgorithmException noSuchAlgo) {
         System.out.println("FF1LS80.Encrypt: Error - No Such Algorithm exists " + noSuchAlgo);
      }
      catch (NoSuchPaddingException noSuchPad) {
         System.out.println("FF1LS80.Encrypt: Error - No Such Padding exists " + noSuchPad);
      }
      catch (InvalidKeyException invalidKey) {
         System.out.println("FF1LS80.Encrypt: Error - Invalid Key " + invalidKey);
      }
      catch (BadPaddingException badPadding) {
         System.out.println("FF1LS80.Encrypt: Error - Bad Padding " + badPadding);
      }
      catch (IllegalBlockSizeException illegalBlockSize) {
         System.out.println("FF1LS80.Encrypt: Error - Illegal Block Size " + illegalBlockSize);
      }
      catch (InvalidAlgorithmParameterException invalidParam) {
         System.out.println("FF1LS80.Encrypt: Error - Invalid Parameter " + invalidParam);
      }
      return Xi; // a result is returned - even if encryption failed
   }

   /*-Decryption-------------------------------------------------------------*/
   
   /* Paraphrased from the draft spec... 
         where Y is the ciphertext message
         where F is the underlying encryption algorithm (AES)

      Decrypt(Key, Tweak, Y) {
         if (method=1) and (Key, Tweak, symbols in Y, and Y length are all valid)
            // (all but length are given or assumed)
            for i = rounds-1 downto 0 {
               B = Y[from bit 1 to bit n-split(n)]
               C = Y[from bit n-split(n)+1 to bit n]
               A = C XOR F(n, T, i, B) 
               Y = A concat B 
            }
            return Y
         end if
      }
      In this implementation, the key is set at instantiation. Just Tweak and Y are passed.
   */
   public byte[] Decrypt(byte[] Tweak, byte[] Yi) throws IllegalArgumentException {
      try {
         validateInput(Yi.length*8);          // make sure this n is known
      }
      catch (IllegalArgumentException e) {
         throw new IllegalArgumentException(); // all lengths must be known in advance
      }
      // BitSets round up to multiples of 64 bits
      BitSet Y  = new BitSet(n);              // the ciphertext
      BitSet B  = new BitSet(remainder);      // first portion of ciphertext - now the larger piece
      int Bsize = (int) Math.ceil(remainder/8.0); // How many bytes will it require? Round up.
      byte[] BCipher  = new byte[Bsize];      // ..as a byte array
      BitSet C  = new BitSet(imbalance);      // remainder of ciphertext - will decrypted
      int Csize = (int) Math.ceil(imbalance/8.0); // How many bytes will it require? Round up.
      byte[] CCipher  = new byte[Csize];      // ..as a byte array
      byte[] A1Cipher = new byte[Bsize];      // interim dec factor from AES
      BitSet Z1 = new BitSet(remainder);      // interim dec factor from AES (as a BitSet)
      BitSet Z2 = new BitSet(imbalance);      // interim dec factor pending XOR with C
      BitSet A  = new BitSet(imbalance);      // interim dec (C and A are the same size)
      byte[] A2Cipher = new byte[Csize];      // ..result for this FF1 round
      try {
         // For AES-CBC from Cipher, PKCS5 is processed internally as PKCS7.
         Cipher AESCBC = Cipher.getInstance("AES/CBC/PKCS5Padding"); // explicit to ensure CBC mode
         AESCBC.init(Cipher.ENCRYPT_MODE, Keys0, new IvParameterSpec(Tweak));
         // ENCRYPT_MODE is not a typo. AES does not decrypt FFX. AES builds a factor.
         // Ready to begin FF1 rounds
         for(int i=rounds-1; i>=0; i=i-1) {
            Y = BitSet.valueOf(Yi);           // byte[] to BitSet
            B = Y.get(0, remainder);          // fromIndex is inclusive and toIndex is exclusive
            if (B.length() < (remainder-8)) { // B.length() is the highest set index +1
               B.set(remainder-8);            // BitSet is short - set bit in last byte
               BCipher = B.toByteArray();     // Convert to byte array and then use
               BCipher[Bsize-1] ^= 0x01;      // ..bitwise xor and clear() to unset
               B.clear(remainder-8);          // ..the forced bit in both locations
            }
            else
               BCipher = B.toByteArray();     // enough bits - use as is
            C = Y.get(remainder, n);
            if (C.length() < (imbalance-8)) { // C.length() is the highest set index +1
               C.set(imbalance-8);            // BitSet is short - set bit in last byte
               CCipher = C.toByteArray();     // Convert to byte array and then use
               CCipher[Csize-1] ^= 0x01;      // ..bitwise xor and clear() to unset
               C.clear(imbalance-8);          // ..the forced bit in both locations
            }
            else
               CCipher = C.toByteArray();     // enough bits - use as is
            // This builds a decryption factor - it does not really decrypt the data
            // This dec factor is the same as the enc factor set in Encrypt()
            A1Cipher = AESCBC.doFinal(BCipher);
            Z1 = BitSet.valueOf(A1Cipher);  
            Z2 = Z1.get(0, imbalance);        // select the relevant bits from the factor
            A = (BitSet) C.clone();           // resync variable names to the spec
            // XOR decrypts this portion using the dec factor
            A.xor(Z2);
            if (A.length() < (imbalance-8)) { // A.length() is the highest set index +1
               A.set(imbalance-8);            // BitSet is short - set bit in last byte
               A2Cipher = A.toByteArray();    // Convert to byte array and then use
               A2Cipher[Csize-1] ^= 0x01;     // ..bitwise xor and clear() to unset
               A.clear(imbalance-8);          // ..the forced bit in both locations
            }
            else
               A2Cipher = A.toByteArray();    // enough bits - use as is
            // Reassemble the partially decrypted message from A || B
            System.arraycopy(A2Cipher, 0, Yi, 0, Csize);
            System.arraycopy(BCipher, 0, Yi, A2Cipher.length, BCipher.length);
            // Yi is ready for the next FF1 round
         }
         // Yi is fully decrypted
      }
      catch (NoSuchAlgorithmException noSuchAlgo) {
         System.out.println("FF1LS80.Decrypt: Error - No Such Algorithm exists " + noSuchAlgo);
      }
      catch (NoSuchPaddingException noSuchPad) {
         System.out.println("FF1LS80.Decrypt: Error - No Such Padding exists " + noSuchPad);
      }
      catch (InvalidKeyException invalidKey) {
         System.out.println("FF1LS80.Decrypt: Error - Invalid Key " + invalidKey);
      }
      catch (BadPaddingException badPadding) {
         System.out.println("FF1LS80.Decrypt: Error - Bad Padding " + badPadding);
      }
      catch (IllegalBlockSizeException illegalBlockSize) {
         System.out.println("FF1LS80.Decrypt: Error - Illegal Block Size " + illegalBlockSize);
      }
      catch (InvalidAlgorithmParameterException invalidParam) {
         System.out.println("FF1LS80.Decrypt: Error - Invalid Parameter " + invalidParam);
      }
      return Yi; // a result is returned - even if decryption failed
   }

}
