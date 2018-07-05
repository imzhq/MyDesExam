package com.hj.test.four;

public class Main {

	private static String key = "12345678901234567890123456789012";
	private static String data = "500800201803290958032018031515520104030109000008262306616310000202136230661631000020213=241122000000030";

	public static void main(String[] args) {
		// byte[] bs = new byte[] { 3, 1, 3, 2, 3, 1, 3, 112, 3, 1, 3, 112, 3, 6, 3, 2
		// };
		// System.out.println(buf2hex(bs));
		DES.encrypt("3331334533313345", "E:\\Desktop\\txt.txt", "1C4A029B156E257A");
	}

	public static String buf2hex(byte abyte0[]) {
		String s = new String();
		for (int i = 0; i < abyte0.length; i++)
			s = s.concat(b2hex(abyte0[i]));

		s = s.toUpperCase();
		// s= s.toLowerCase();
		return s;
	}

	public static String b2hex(byte byte0) {
		String s = Integer.toHexString(byte0 & 0xff);
		String s1;
		if (s.length() == 1)
			s1 = "0".concat(s);
		else
			s1 = s;
		return s1.toUpperCase();
	}

	/**
	 * 字节数组转HEXDECIMAL
	 * 
	 * @param bArray
	 * @return
	 */
	public static final String bytesToHexString(byte[] bArray) {
		StringBuffer sb = new StringBuffer(bArray.length);
		String sTemp;
		for (int i = 0; i < bArray.length; i++) {
			sTemp = Integer.toHexString(0xFF & bArray[i]);
			if (sTemp.length() < 2)
				sb.append(0);
			sb.append(sTemp.toUpperCase());
		}
		return sb.toString();
	}

}
