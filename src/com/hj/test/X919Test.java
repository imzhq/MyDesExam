package com.hj.test;

import java.security.GeneralSecurityException;

public class X919Test {

	private static String mak_ming = "1C4A029B156E257A80572F6B4692CBCB";
	private static String data = "500800201803290958032018031515520104030109000008262306616310000202136230661631000020213=241122000000030";

	public static void main(String[] args) throws GeneralSecurityException {
		System.out.println(ISO9797Alg3MacTest.bytesToHex(calculateANSIX9_19MAC(mak_ming.getBytes(), data.getBytes())));
	}

	public static byte[] calculateANSIX9_19MAC(byte[] key, byte[] data) throws GeneralSecurityException {
		if (key == null || data == null)
			return null;

		if (key.length != 16) {
			throw new RuntimeException("秘钥长度错误.");
		}

		byte[] keyLeft = new byte[8];
		byte[] keyRight = new byte[8];
		System.arraycopy(key, 0, keyLeft, 0, 8);
		System.arraycopy(key, 8, keyRight, 0, 8);

		byte[] result99 = calculateANSIX9_9MAC(keyLeft, data);

		byte[] resultTemp = DesUtils.decryptByDesEcb(result99, keyRight);
		return DesUtils.encryptByDesEcb(resultTemp, keyLeft);
	}

	/**
	 * ANSI X9.9MAC算法 <br/>
	 * (1) ANSI X9.9MAC算法只使用单倍长密钥。 <br/>
	 * (2) MAC数据先按8字节分组，表示为D0～Dn，如果Dn不足8字节时，尾部以字节00补齐。 <br/>
	 * (3) 用MAC密钥加密D0，加密结果与D1异或作为下一次的输入。 <br/>
	 * (4) 将上一步的加密结果与下一分组异或，然后再用MAC密钥加密。<br/>
	 * (5) 直至所有分组结束，取最后结果的左半部作为MAC。<br/>
	 * 采用x9.9算法计算MAC (Count MAC by ANSI-x9.9).
	 * 
	 * @param key
	 *            8字节密钥数据
	 * @param data
	 *            待计算的缓冲区
	 * @throws GeneralSecurityException
	 */
	public static byte[] calculateANSIX9_9MAC(byte[] key, byte[] data) throws GeneralSecurityException {

		final int dataLength = data.length;
		final int lastLength = dataLength % 8;
		final int lastBlockLength = lastLength == 0 ? 8 : lastLength;
		final int blockCount = dataLength / 8 + (lastLength > 0 ? 1 : 0);

		// 拆分数据（8字节块/Block）
		byte[][] dataBlock = new byte[blockCount][8];
		for (int i = 0; i < blockCount; i++) {
			int copyLength = i == blockCount - 1 ? lastBlockLength : 8;
			System.arraycopy(data, i * 8, dataBlock[i], 0, copyLength);
		}

		byte[] desXor = new byte[8];
		for (int i = 0; i < blockCount; i++) {
			byte[] tXor = DesUtils.xOr(desXor, dataBlock[i]);
			desXor = DesUtils.encryptByDesEcb(tXor, key); // DES加密
		}
		return desXor;
	}

}
