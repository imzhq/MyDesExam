package com.hj.test.util;

/**
 * Created by nickname on 2018/7/2.
 */
public class Mac3DesUtils {
	private static final String TAG = "Mac3DesUtils";
	private static String key = "12345678901234567890123456789012";
	private static String cipherKey = "A3EBF3A0A4102874BE640E5951D0ACE3";
	private static String clearKey = "1C4A029B156E257A80572F6B4692CBCB";
	public static byte[] IV = new byte[8];

	public static byte byteXOR(byte src, byte src1) {
		return (byte) ((src & 0xFF) ^ (src1 & 0xFF));
	}

	/**
	 * 等长byte[] 异或
	 *
	 * @param src
	 * @param src1
	 * @return
	 */
	public static byte[] bytesXOR(byte[] src, byte[] src1) {
		int length = src.length;
		if (length != src1.length) {
			return null;
		}
		byte[] result = new byte[length];
		for (int i = 0; i < length; i++) {
			result[i] = byteXOR(src[i], src1[i]);
		}
		return result;
	}

	/**
	 * mac计算,数据不为8的倍数，需要补0，将数据8个字节进行异或，再将异或的结果与下一个8个字节异或，一直到最后，将异或后的数据进行DES计算
	 *
	 * @param key
	 * @param Input
	 * @return
	 */
	public static byte[] clacMac(byte[] key, byte[] Input) {
		// Log.i(TAG, "key is " + new String(key) + " ,data is " + new String(Input));
		int length = Input.length;
		int x = length % 8;
		int addLen = 0;
		if (x != 0) {
			addLen = 8 - length % 8;
		}
		int pos = 0;
		byte[] data = new byte[length + addLen];
		System.arraycopy(Input, 0, data, 0, length);
		byte[] oper1 = new byte[8];
		System.arraycopy(data, pos, oper1, 0, 8);
		pos += 8;
		for (int i = 1; i < data.length / 8; i++) {
			byte[] oper2 = new byte[8];
			System.arraycopy(data, pos, oper2, 0, 8);
			byte[] t = bytesXOR(oper1, oper2);
			// System.out.println(bytesToHexString(t));
			oper1 = t;
			pos += 8;
		}
		// 将异或运算后的最后8个字节（RESULT BLOCK）转换成16个HEXDECIMAL：
		// 第一步正确
		String mac_tmp = bytesToHexString(oper1);
		// System.out.println("first xor mac_tmp:" + mac_tmp);
		byte[] resultBlock = mac_tmp.getBytes();
		// 取前8个字节用mkey1，DES加密
		byte[] front8 = new byte[8];
		System.arraycopy(resultBlock, 0, front8, 0, 8);
		byte[] behind8 = new byte[8];
		System.arraycopy(resultBlock, 8, behind8, 0, 8);
		String hexdecimal16 = bytesToHexString(front8) + bytesToHexString(behind8);
		// System.out.println("16个HEXDECIMAL:" + hexdecimal16);
		String encryption8 = MacEcbUtils.encryptDES(clearKey, hexdecimal16).substring(0, 16);
		// System.out.println("前8字节加密结果:" + encryption8);

		// byte[] desfront8 = DesUtils.encrypt(front8, key);
		// 将加密后的结果与后8 个字节异或：
		// byte[] resultXOR = bytesXOR(behind8, encryption8.getBytes());
		String resultXORHex = xorHex(encryption8, bytesToHexString(behind8));
		// System.out.println("与后8字节异或结果:" + resultXORHex);

		// 用异或的结果TEMP BLOCK 再进行一次单倍长密钥算法运算
		// byte[] buff = DesUtils.encrypt(resultXOR, key);

		String encry2 = MacEcbUtils.encryptDES(clearKey, resultXORHex + "0000000000000000");
		// System.out.println("再加密结果：" + encry2);
		byte[] retBuf = encry2.substring(0, 8).getBytes();
		// System.out.println("16个HEXDECIMAL：" + bytesToHexString(retBuf));
		// System.out.println("MAC 字符串形式:" + encry2.substring(0, 8));
		// 将运算后的结果（ENC BLOCK2）转换成16 个HEXDECIMAL asc
		// 取8个长度字节
		return retBuf;
	}

	/**
	 * hex异或
	 *
	 * @param a
	 * @param b
	 * @return
	 */
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

	/**
	 * bytes转String
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

	public static void main(String[] args) {
		// byte[] entryKey = new byte[0];
		// try {
		// entryKey = key.getBytes("UTF-8");
		// } catch (UnsupportedEncodingException e) {
		// e.printStackTrace();
		// }
		// String input_str =
		// "500800201803290958032018031515520104030109000008262306616310000202136230661631000020213"
		// +
		// "=241122000000030";
		// // byte[] input = new byte[]{0x01, 0x02, 0x03};
		// byte[] input = new byte[0];
		// try {
		// input = input_str.getBytes("UTF-8");
		// } catch (UnsupportedEncodingException e) {
		// e.printStackTrace();
		// }
		// clacMac(entryKey, input);

		System.out.println(
				MacEcbUtils.decryptDES("12345678901234567890123456789012", "A3EBF3A0A4102874BE640E5951D0ACE3"));
	}

}
