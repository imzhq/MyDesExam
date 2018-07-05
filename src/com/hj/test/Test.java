package com.hj.test;

import java.math.BigDecimal;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

public class Test {

	public static void main(String[] args) {
		// BigDecimal tBigDecimal = new BigDecimal("6");
		// System.out.println(tBigDecimal);
		// System.out.println(tBigDecimal.doubleValue());
		// System.out.println(tBigDecimal.intValue());
		// System.out.println(tBigDecimal.toEngineeringString());
		// System.out.println(tBigDecimal.toPlainString());
		// System.out.println(tBigDecimal.toString());
		// System.out.println(tBigDecimal.setScale(1));
		// System.out.println(tBigDecimal.toString());

		System.out.println(MacUtil.getByteStr(MacUtil.bcd2Bcd("313E313E343A3004".getBytes())));
	}

	public static String xorHex(String a, String b) {
		// TODO: Validation
		char[] chars = new char[a.length()];
		for (int i = 0; i < chars.length; i++) {
			chars[i] = toHex(fromHex(a.charAt(i)) ^ fromHex(b.charAt(i)));
		}
		return new String(chars);
	}

	private static int fromHex(char c) {
		if (c >= '0' && c <= '9') {
			return c - '0';
		}
		if (c >= 'A' && c <= 'F') {
			return c - 'A' + 10;
		}
		if (c >= 'a' && c <= 'f') {
			return c - 'a' + 10;
		}
		throw new IllegalArgumentException();
	}

	private static char toHex(int nybble) {
		if (nybble < 0 || nybble > 15) {
			throw new IllegalArgumentException();
		}
		return "0123456789ABCDEF".charAt(nybble);
	}

}
