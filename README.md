# FFXDemo
Example implementation of FFX targeting ADS-B 1090ES
<BR>2015 May 16, Michael Vose

Use FFX_test.java as an example of how to instantiate the FF1LS80 class and invoke its methods.

FFX refers to (F)ormat-Preserving (F)eistel-Based (X)-family of algorithms. In this case, the FF1LS80 class implements the FF1 algorithm with parameters favorable to processing an ADS-B extended squitter message. Feistel Method Left is used to increase the imbalance factor to a split of 24 bits left and 80 bits right. The remaining left-most 8 bits of the 112-bit extended squitter are unencrypted and used as the basis of the Tweak, (an initialization vector.)

This is an academic implementation intended to follow the draft specification while using Java and remaining compatible with Android. It is not optimized. The terminology, variable names, and methods employed here follow the original ffx-spec.pdf document rather than the later variations and proposals. Please refer to the program comments for additional information.

For a detailed discussion of the FF1 algorithm of FFX, 
<BR>refer to https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/proposed-modes/ffx/ffx-spec.pdf.

For a detailed discussion of unbalanced Feistel networks, 
<BR>refer to https://www.schneier.com/wp-content/uploads/2016/02/paper-unbalanced-feistel.pdf.
