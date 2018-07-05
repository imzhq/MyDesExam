package com.hj.test;

import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.util.encoders.Hex;

public class MacUtil {
	private static String key = "1C4A029B156E257A80572F6B4692CBCB";
	private static String data = "500800201803290958032018031515520104030109000008262306616310000202136230661631000020213=241122000000030";

	// des-ecb方式加密解密的key
	public static final String DES_ECB_KEY = "1C4A029B156E257A80572F6B4692CBCB";
	public static final String data_des = "3331334533313345";

	public static void main(String[] args) throws Exception {
		// doMac(key, data);
		// System.out.println(xorHex("EA86E04B5BD4C5F0", "3334334133303034"));
		// byte[] bs = new byte[] { 120, 124, -17, -65, -67, -17, -65, -67, 115, -52,
		// -72, 9, 61, 67, 65, 106, -17, -65,
		// -67, 61, 69, 27 };
		System.out.println(getByteStr(hexStringToByte("5008572018070318061720180117145300170060001000031")));
	}

	public static void StringToAsc() { // 字符串转换为ASCII码
		String s = "5008572018070318061720180117145300170060001000031";
		char[] chars = s.toCharArray();
		for (int i = 0; i < chars.length; i++) {
			System.out.println(" " + chars[i] + " " + (int) chars[i]);
		}
	}

	public static void test() {
	}

	public static String doMac(String key, String data) throws Exception {
		byte[] data_byte = data.getBytes();
		byte[] key_byte = key.getBytes();
		// 判断位数,补齐
		int length = data_byte.length;
		if (length % 8 != 0) {
			length = ((length / 8) + 1) * 8;
		}
		byte[] data_r = new byte[length];
		System.arraycopy(data_byte, 0, data_r, 0, data_byte.length);
		for (int i = data_byte.length; i < length; i++) {
			data_r[i] = 0x00;
		}
		String MAB = bcd2Str(data_r);
		// 展示MAB
		List<String> mabs = new ArrayList<>();
		for (int i = 0; i < MAB.length() / 16; i++) {
			mabs.add(MAB.substring(i * 16, (i + 1) * 16));
		}
		System.out.println();

		// 构建正确的结果集
		List<String> strings = new ArrayList<>();
		strings.add("0408000B02090209");
		strings.add("3130303830393331");
		strings.add("0103010D010C0603");
		strings.add("31323139313F3632");
		strings.add("010B0109010F060A");
		strings.add("333D333A3139303B");
		strings.add("050E020A01090009");
		strings.add("353C3339373B3339");
		strings.add("030A020F040A0309");
		strings.add("333A303F363B3034");
		strings.add("010E010E04090004");
		strings.add("313E313E343A3004");

		System.out.println("第0组明文：" + mabs.get(0));
		System.out.println("第1组明文：" + mabs.get(1));

		// byte[] xor_1_1 = bytesXOR(mabs.get(0).getBytes(), mabs.get(1).getBytes());
		// // 扩展Str
		// String xor_1 = processBytes(xor_1_1);
		String xor_1 = xorHex(mabs.get(0), mabs.get(1));
		System.out.println("第1组异或结果：" + xor_1);
		if (xor_1.equals(strings.get(0).trim())) {
			System.out.println("结果正确");
		} else {
			System.out.println("结果错误");
		}
		System.out.println();

		for (int i = 2; i < mabs.size(); i++) {
			System.out.println("第" + i + "组明文：" + mabs.get(i));
			xor_1 = xorHex(xor_1, mabs.get(i));
			// xor_1_1 = bytesXOR(xor_1_1, mabs.get(i).getBytes());
			// xor_1 = processBytes(xor_1_1);
			System.out.println("第" + i + "组异或结果" + xor_1);
			if (i < 13 && strings.get(i - 1).trim().equals(xor_1)) {
				System.out.println("结果正确");
			} else {
				System.out.println("结果错误");
				System.out.println("正确结果是: " + strings.get(i - 1).trim());
			}
			System.out.println();
		}
		byte[] n_des = bcd2Bcd(xor_1.getBytes());

		ENCRYPTMethod(Hex.decode("3331334533313345"), Hex.decode("1C4A029B156E257A80572F6B4692CBCB"));

		String n_des_str = getByteStrD(n_des);
		System.out.println(getByteStr(n_des));

		byte[] left = new byte[16];
		System.arraycopy(n_des, 0, left, 0, left.length);
		// 80572F6B4692CBCB
		ENCRYPTMethod(n_des_str.substring(0, 16), "1C4A029B156E257A80572F6B4692CBCB");
		// System.out.println(bcd2Str(bytes));
		return "";
	}

	public static byte[] hexStringToByte(String hex) {
		int len = (hex.length() / 2);
		byte[] result = new byte[len];
		char[] achar = hex.toCharArray();
		for (int i = 0; i < len; i++) {
			int pos = i * 2;
			result[i] = (byte) (toByte(achar[pos]) << 4 | toByte(achar[pos + 1]));
		}
		return result;
	}

	private static byte toByte(char c) {
		byte b = (byte) "0123456789ABCDEF".indexOf(c);
		return b;
	}

	/**
	 * DES加密
	 *
	 * @param HexString
	 *            字符串（16位16進制字符串）
	 * @param keyStr
	 *            密鑰16個1
	 * @throws Exception
	 */
	public static void ENCRYPTMethod(String HexString, String keyStr) throws Exception {
		try {
			byte[] theKey = null;
			byte[] theMsg = null;
			theMsg = hexToBytes(HexString);
			theKey = hexToBytes(keyStr);
			KeySpec ks = new DESKeySpec(theKey);
			SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
			SecretKey ky = kf.generateSecret(ks);
			Cipher cf = Cipher.getInstance("DES/ECB/NoPadding");
			cf.init(Cipher.ENCRYPT_MODE, ky);
			byte[] theCph = cf.doFinal(theMsg);
			System.out.println("*************DES加密****************");
			System.out.println("密鑰 : " + bytesToHex(theKey));
			System.out.println("字符串: " + bytesToHex(theMsg));
			System.out.println("加密後: " + bytesToHex(theCph));
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * DES加密
	 *
	 * @param HexString
	 *            字符串（16位16進制字符串）
	 * @param keyStr
	 *            密鑰16個1
	 * @throws Exception
	 */
	public static void ENCRYPTMethod(byte[] theMsg, byte[] theKey) throws Exception {
		try {
			KeySpec ks = new DESKeySpec(theKey);
			SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
			SecretKey ky = kf.generateSecret(ks);
			Cipher cf = Cipher.getInstance("DES/ECB/NoPadding");
			cf.init(Cipher.ENCRYPT_MODE, ky);
			byte[] theCph = cf.doFinal(theMsg);
			System.out.println("*************DES加密****************");
			System.out.println("密鑰    : " + bytesToHex(theKey));
			System.out.println("字符串: " + bytesToHex(theMsg));
			System.out.println("加密後: " + bytesToHex(theCph));
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
	}

	public static byte[] hexToBytes(String str) {
		if (str == null) {
			return null;
		} else if (str.length() < 2) {
			return null;
		} else {
			int len = str.length() / 2;
			byte[] buffer = new byte[len];
			for (int i = 0; i < len; i++) {
				buffer[i] = (byte) Integer.parseInt(str.substring(i * 2, i * 2 + 2), 16);
			}
			return buffer;
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

	/**
	 * 处理xor结果 ,先扩展,后压缩
	 * 
	 * @param source
	 * @return
	 */
	public static String processBytes(byte[] source) {
		System.out.println("processBytes source array : " + getByteStr(source));
		byte[] b2 = bcd2Bcd(source);
		System.out.println("processBytes 1 : " + getByteStr(b2));
		byte[] result = new byte[b2.length / 2];
		String delete = "";
		for (int i = 0; i < b2.length; i++) {
			if (i % 2 == 0) {
				// 两个数组合并有问题
				// 113 ==> 8, 112 ==> 70, 112==> F, 116==> D, 112==> B
				result[i / 2] = (byte) b2[i + 1];
			} else {
				delete += b2[i - 1] + " ";
			}
		}
		System.out.println("delete str is " + delete);
		return buildHexStr(result);
	}

	public static String buildHexStr(byte[] source) {
		System.out.println("buildHexStr " + getByteStr(source));
		String reString = "";
		for (int i = 0; i < source.length; i++) {
			// 处理大于16的结果
			if (source[i] > 15) {
				if (source[i] % 16 > 0)
					reString += (source[i] / 16) + 1;
				else
					reString += (source[i] / 16);
			} else {
				reString += "0123456789ABCDEF".charAt(source[i]);
			}
		}
		return reString;
	}

	public static String getXorResult(String source) throws Exception {
		System.out.println("getXorResult source is " + source);
		String single = "";
		for (int i = 0; i < source.length() - 1; i++) {
			if (i % 2 == 0) {
				single += "0123456789ABCDEF"
						.charAt((getIntByChar(source.charAt(i)) + getIntByChar(source.charAt(i + 1))));
			}
		}
		return single;
	}

	/**
	 * 将十六进制A--F转换成对应数
	 * 
	 * @param ch
	 * @return
	 * @throws Exception
	 */
	public static int getIntByChar(char ch) throws Exception {
		char t = Character.toUpperCase(ch);
		int i = 0;
		switch (t) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			i = Integer.parseInt(Character.toString(t));
			break;
		case 'A':
			i = 10;
			break;
		case 'B':
			i = 11;
			break;
		case 'C':
			i = 12;
			break;
		case 'D':
			i = 13;
			break;
		case 'E':
			i = 14;
			break;
		case 'F':
			i = 15;
			break;
		default:
			throw new Exception("getIntByChar was wrong");
		}
		return i;
	}

	/**
	 * 单字节异或
	 * 
	 * @param src1
	 * @param src2
	 * @return
	 */
	public static byte byteXOR(byte src1, byte src2) {
		return (byte) ((src1 & 0xFF) ^ (src2 & 0xFF));
	}

	/**
	 * 字节数组异或
	 * 
	 * @param src1
	 * @param src2
	 * @return
	 */
	public static byte[] bytesXOR(byte[] src1, byte[] src2) {
		int length = src1.length;
		if (length != src2.length) {
			return null;
		}
		byte[] result = new byte[length];
		for (int i = 0; i < length; i++) {
			result[i] = byteXOR(src1[i], src2[i]);
		}
		return result;
	}

	/**
	 * 
	 * 两个等长的数组做异或
	 * 
	 * @param source1
	 * 
	 * @param source2
	 * 
	 * @return
	 * 
	 */
	public static int[] diffOr(int[] source1, int[] source2) {
		int len = source1.length;
		int[] dest = new int[len];
		for (int i = 0; i < len; i++) {
			dest[i] = source1[i] ^ source2[i];
		}
		return dest;
	}

	public static String getByteStr(byte[] in) {
		String re = "";
		for (int b : in) {
			re += b + " ";
		}
		return re;
	}

	public static String getByteStrD(byte[] in) {
		String re = "";
		for (int b : in) {
			re += b;
		}
		return re;
	}

	// 把16进制序数恢复成十进制
	public static byte[] bcd2Bcd(byte[] bytes) {
		byte[] res = new byte[bytes.length * 2];
		byte b3 = -127;
		for (int i = 0; i < bytes.length; i++) {
			byte b1 = (byte) ((bytes[i] & 0xf0) >>> 4);
			byte b2 = (byte) (bytes[i] & 0x0f);
			// res[i * 2] = b1;
			// res[i * 2 + 1] = b2;

			// 判断b3是不是初始值,初始值的话赋值
			if (b3 == -127) {
				b3 = b1;
			}
			// 如果b3!=b1,进行反序插值,否则正序插值
			// if (b3 != b1) {
			// res[i * 2] = b3;
			// if (b2 % b1 > 0) {
			// res[i * 2 + 1] = (byte) ((b2 / b1) + 1);
			// } else
			// res[i * 2 + 1] = (byte) (b2 / b1);
			// } else {
			res[i * 2] = b1;
			res[i * 2 + 1] = b2;
			// }
		}
		return res;
	}

	public static String bcd2Str(byte[] bytes) {
		StringBuffer temp = new StringBuffer(bytes.length * 2);
		System.out.print("bcd2Str ");
		for (int i = 0; i < bytes.length; i++) {
			byte b1 = (byte) ((bytes[i] & 0xf0) >>> 4);
			temp.append("0123456789ABCDEF".charAt(b1));
			System.out.print(b1 + " ");
			byte b2 = (byte) (bytes[i] & 0x0f);
			temp.append("0123456789ABCDEF".charAt(b2));
			System.out.print(b2 + " ");
		}
		System.out.println();
		return temp.toString().substring(0, 1).equalsIgnoreCase("0") ? temp.toString().substring(1) : temp.toString();
	}

	///////////////////////////////////////
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
