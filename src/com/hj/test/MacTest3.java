package com.hj.test;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.util.encoders.Hex;

public class MacTest3 {
	public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException {
		byte[] KEY_DATA = hexStringToByteArray("1C4A029B156E257A80572F6B4692CBCB");
		DESEngine des = new DESEngine();
		ISO9797Alg3Mac mac = new ISO9797Alg3Mac(des, 32);
		mac.init(new DESedeParameters(KEY_DATA));

		byte[] data = "500800201803290958032018031515520104030109000008262306616310000202136230661631000020213"
				.getBytes("utf-8");
		byte[] result = new byte[mac.getMacSize()];

		mac.update(data, 0, data.length);
		mac.doFinal(result, 0);

		System.out.println("firma=" + new String(Hex.encode(result)));
	}

	private static byte[] hexStringToByteArray(String hex) {
		int len = hex.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
		}
		return data;
	}
}
