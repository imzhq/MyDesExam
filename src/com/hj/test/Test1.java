package com.hj.test;

import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.*;

/**
 *
 * @author http://myprogramminglab.blogspot.com
 */
public class Test1 {

	public static void main(String[] args) {
		// add the security provider
		// not required if you have Install the library
		// by Configuring the Java Runtime
		Security.addProvider(new BouncyCastleProvider());

		// DES only accept encryption key with
		// 8 bytes length only
		byte[] EncryptionKey = { 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78 };

		// DES without padding must contains
		// data length n * 8
		byte[] input = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x18 };

		// show the input to the screen
		System.out.println("Input: " + new String(Hex.encode(input)));

		SecretKeySpec key = new SecretKeySpec(EncryptionKey, "DES");

		try {

			// get the cipher instance
			Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding", "BC");

			// init the cipher
			cipher.init(Cipher.ENCRYPT_MODE, key);

			// get the output length
			byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

			int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
			ctLength += cipher.doFinal(cipherText, ctLength);

			// show the encrypted text to the screen
			System.out.println("Encrypted Input: " + new String(Hex.encode(cipherText)));

			// decrypt it back
			cipher.init(Cipher.DECRYPT_MODE, key);

			// get the output text (decrypted text
			byte[] decryptedText = new byte[cipher.getOutputSize(input.length)];

			ctLength = cipher.update(cipherText, 0, cipherText.length, decryptedText, 0);
			ctLength += cipher.doFinal(decryptedText, ctLength);

			// show the decrypted text to the screen
			System.out.println("Decrypted Input: " + new String(Hex.encode(decryptedText)));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
