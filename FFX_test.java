/* EEL4915 - Develop prototype FFX encryption and decryption
   2015 May 16, Michael Vose
   FFX=(F)ormat-Preserving (F)eistel-Based (X)-family of algorithms.
   Top-Level stub for testing methods.
*/
public class FFX_test {

	public static final void main(String args[]) {
      String keyStr;                // 128 bits in 32 hexidecimal digits
      int    n;                     // message (input) length in bits
      int    rc = 0;                // code from FF1LS80.addValidSize(n)
      byte   preTweak;              // 8 bits - the basis of an enc/dec IV
      byte[] Tweak = new byte[16];  // 128 bits for 16 copies of the preTweak
      byte[] Xi    = new byte[13];  // 104 bits in 13 bytes - test enc input
      byte[] Xo    = new byte[13];  // 104 bits in 13 bytes - test enc output
      byte[] Yi    = new byte[13];  // 104 bits in 13 bytes - test dec input
      byte[] Yo    = new byte[13];  // 104 bits in 13 bytes - test dec output

      // Warning: keyStr must never be embedded this way in production.
      keyStr = "0102030405060708090A0B0C0D0E0F16"; // Use hex pairs to load the key.

		FF1LS80 FFXADSB = new FF1LS80(keyStr); // Instantiate the class one time. This sets 
                                             // ..the key and builds some parameters.

      n = 104;                      // ADS-B 1090ES, (aka Extended squitter,) is 112 
                                    // ..bits, (without preamble.) Only the last 104
                                    // ..bits are subject to FFX enc/dec. In general,
                                    // ..n>=16 bits. Given the unbalanced split() in use,
                                    // ..n>=88 bits. The principle factors are:
                                    // ..n must be byte-aligned, (a multiple of 8.)
                                    // ..n must be the size of the data to be enc/dec.
                                    // So, if you adapt this to other target sizes,
                                    // ..you may need to pad the data to align it.
                                    // ..If you pad the data prior to enc, remember to 
                                    // ..remove the pad after dec.

      rc = FFXADSB.addValidSize(n); // only valid, anticipated n sizes are permitted
      if (rc > 1) {                 // duplicate n (rc=1) is ignored (warning)
         return;                    // out-of-range n (rc=2) is not permitted (error)
      }                             // Invoke this method for each possible n found in
                                    // ..the input data before attempting to enc/dec.
                                    // this completes the FF1 parameter set

      // Warning: Tweak must never be embedded this way in production. Use real data.
      preTweak = 0x57;              // Use the first 8 bits of the extended squitter,
                                    // ..(not the preamble.) 0x57 is only a test value.
      for (int i=0; i<16; i=i+1) {  // Repeat it to fill 16 bytes - this is an IV. The 
         Tweak[i] = preTweak;       // ..Tweak must be a repeatable function of the 
      }                             // ..unencrypted portion of the ADS-B message.

      Xi = FFXADSB.hexToBytes("0102030405060708090A0B0C13"); // Simulated message input
      System.out.println("Xi:    " + FFXADSB.bytesToHex(Xi));

      try {
         Xo = FFXADSB.Encrypt(Tweak, Xi); // Encrypt each plaintext input (Xi)
         Yi = Xo;                         // FFX never changes the message size
         System.out.println("Xo/Yi: " + FFXADSB.bytesToHex(Xo));
      }
      catch (IllegalArgumentException e) {
         System.exit(3);
      }

      try {
         Yo = FFXADSB.Decrypt(Tweak, Yi); // Decrypt each ciphertext input (Yi)
         System.out.println("Yo:    " + FFXADSB.bytesToHex(Yo));
      }
      catch (IllegalArgumentException e) {
         System.exit(4);
      }
   }
	
}
