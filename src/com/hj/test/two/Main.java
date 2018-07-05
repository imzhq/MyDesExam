package com.hj.test.two;

import java.security.GeneralSecurityException;

import com.hj.test.MacUtil;

public class Main {
	private static String key = "12345678901234567890123456789012";
	private static String data = "500800201803290958032018031515520104030109000008262306616310000202136230661631000020213=241122000000030";

	public static void main(String[] args) throws GeneralSecurityException {
		System.out.println(bcd2Str(
				ANSIMacUtils.calculateANSIX9_19MAC(MacUtil.bcd2Bcd(key.getBytes()), MacUtil.bcd2Bcd(data.getBytes()))));
	}

	public static String bcd2Str(byte[] b) {
		char[] HEX_DIGITS = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
				'F' };
		StringBuilder sb = new StringBuilder(b.length * 2);

		for (int i = 0; i < b.length; ++i) {
			sb.append(HEX_DIGITS[(b[i] & 240) >>> 4]);
			sb.append(HEX_DIGITS[b[i] & 15]);
		}

		return sb.toString();
	}

}
