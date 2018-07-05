package com.hj.test;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class MacTest4 {
	public static void main(String[] args) {
		// try {
		// String claveFirmar = "1C4A029B156E257A80572F6B4692CBCB";
		// byte[] claveFirmarBytes = hexStringToByteArray(claveFirmar);
		//
		// String textoFirmar =
		// "500800201803290958032018031515520104030109000008262306616310000202136230661631000020213=241122000000030";
		// byte[] textoFirmarBytes = textoFirmar.getBytes("utf-8");
		//
		// byte[] allBytes = retailMac(claveFirmarBytes, textoFirmarBytes);
		// byte[] firmaBytes = Arrays.copyOf(allBytes, 4);
		// String firma = toHex(firmaBytes);
		//
		// System.out.println("firma=" + firma);
		// } catch (Exception e) {
		// e.getStackTrace();
		// }

		byte[] bs = new byte[] { 0, 0, 0, 1, 0, 0, 0, 14, 0, 0, 0, 1, 0, 0, 0, 14, 0, 0, 0, 4, 0, 0, 0, 9, 0, 0, 0, 0,
				0, 0, 13, 7 };
		System.out.println(toHex(bs));
	}

	private static byte[] hexStringToByteArray(String hex) {
		int len = hex.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
		}
		return data;
	}

	final private static String toHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	private static byte[] retailMac(byte[] key, byte[] data) {
		try {
			// Create Keys
			byte[] key1 = Arrays.copyOf(key, 8);
			byte[] key2 = Arrays.copyOfRange(key, 8, 16);

			// ISO/IEC 9797-1 or ISO 7816d4 Padding for data (adding 80 00 ..)
			byte[] pdata = addPadding(data);

			SecretKeyFactory mySecretKeyFactory = SecretKeyFactory.getInstance("DES");

			DESKeySpec myKeySpec1 = new DESKeySpec(key1);
			SecretKey myKey1 = mySecretKeyFactory.generateSecret(myKeySpec1);
			Cipher cipher1 = Cipher.getInstance("DES/CBC/NoPadding");
			cipher1.init(Cipher.ENCRYPT_MODE, myKey1, new IvParameterSpec(new byte[8]));

			DESKeySpec myKeySpec2 = new DESKeySpec(key2);
			SecretKey myKey2 = mySecretKeyFactory.generateSecret(myKeySpec2);
			Cipher cipher2 = Cipher.getInstance("DES/CBC/NoPadding");
			cipher2.init(Cipher.DECRYPT_MODE, myKey2, new IvParameterSpec(new byte[8]));

			byte[] result = cipher1.doFinal(pdata);

			byte[] block = Arrays.copyOfRange(result, result.length - 8, result.length);

			// Decrypt the resulting block with Key-2
			block = cipher2.doFinal(block);

			// Encrypt the resulting block with Key-1
			block = cipher1.doFinal(block);

			return block;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	private static byte[] addPadding(byte[] in) {
		int extra = 8 - (in.length % 8);
		int newLength = in.length + extra;
		byte[] out = Arrays.copyOf(in, newLength);
		int offset = in.length;
		// out[offset] = (byte) 0x80;
		// offset++;
		while (offset < newLength) {
			out[offset] = (byte) 0;
			offset++;
		}
		return out;
	}
}
