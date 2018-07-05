package com.hj.test.five;

import java.io.UTFDataFormatException;
import java.nio.charset.Charset;

import org.omg.PortableInterceptor.SYSTEM_EXCEPTION;

public class Main {

	private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

		try {
			String textClar = "CRIPTEAZA ASTA";

			textClar = "33313345333133453334334133303034";
			// DES
			String k = "1C4A029B156E257A80572F6B4692CBCB";
			System.out.println("Text clar: " + textClar);
			byte[] enc = DES.encrypt(textClar.getBytes(), k.getBytes());
			System.out.println("Text criptat DES: " + bytesToHex(enc));
			System.out.println("Text criptat DES: " + new String(enc));

			byte[] dec = DES.decrypt(enc, k.getBytes());
			System.out.println("Text decriptat DES: " + new String(dec));
			System.out.println("------------------");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static String bytesToHex(byte[] data) {
		if (data == null) {
			return null;
		} else {
			int len = data.length;

			StringBuffer sb = new StringBuffer(data.length);
			String sTemp;
			// String str = "";
			for (int i = 0; i < len; i++) {
				// if ((data[i] & 0xFF) < 16)
				// str = str + "0" + java.lang.Integer.toHexString(data[i] & 0xFF);
				// else
				// str = str + java.lang.Integer.toHexString(data[i] & 0xFF);

				sTemp = Integer.toHexString(0xFF & data[i]);
				if (sTemp.length() < 2)
					sb.append(0);
				sb.append(sTemp.toUpperCase());
			}
			return sb.toString();
		}
	}

}
