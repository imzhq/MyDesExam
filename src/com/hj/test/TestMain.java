package com.hj.test;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.params.DESParameters;

import com.hj.test.two.DesUtils;

public class TestMain {

	private static String mkey = "A3EBF3A0A4102874BE640E5951D0ACE3";
	private static String mak_mi = "A3EBF3A0A4102874BE640E5951D0ACE3";
	private static String mak_ming = "1C4A029B156E257A80572F6B4692CBCB";
	private static String data = "500800201803290958032018031515520104030109000008262306616310000202136230661631000020213=241122000000030";

	public static void main(String[] args) throws GeneralSecurityException {
		System.out.println(getByteStr(mak_ming.getBytes()));
		System.out.println("mak_mi length is " + mak_ming.getBytes().length);
		System.out.println();

		System.out.println(getByteStr(mak_mi.getBytes()));
		System.out.println("mak_ming length is " + mak_mi.getBytes().length);
		System.out.println();

		DESEngine desEngine = new DESEngine();
		DESParameters desParameters = new DESParameters(mak_ming.getBytes());
		byte[] in = data.getBytes();
		byte[] out = new byte[1024];
		desEngine.init(true, desParameters);
		desEngine.processBlock(in, 0, out, 0);

		Mac(mkey, data);
	}

	public static String Mac(String key, String data) throws GeneralSecurityException {
		byte[] zero_byte = new byte[8];
		zero_byte[0] = 0x00;
		zero_byte[1] = 0x00;
		zero_byte[2] = 0x00;
		zero_byte[3] = 0x00;
		zero_byte[4] = 0x00;
		zero_byte[5] = 0x00;
		zero_byte[6] = 0x00;
		zero_byte[7] = 0x00;
		byte[] data_byte = data.getBytes();
		byte[] key_byte = key.getBytes();

		System.out.println(getByteStr(data_byte));
		System.out.println("data length is " + data_byte.length);

		System.out.println();

		System.out.println(getByteStr(key_byte));
		System.out.println("key length is " + key_byte.length);

		// 1、分散终端主密钥得到MAK
		//
		// 2、MAC计算数据 = MAB，如果MAB数据长度不是8字节整数倍 则用0x00填充至8字节整数倍；如果正好是整数倍，则不填充。
		byte[] temp = new byte[10];
		for (;;) {
			if (data_byte.length % 8 != 0) {
				temp = new byte[data_byte.length + 1];
				System.arraycopy(data_byte, 0, temp, 0, data_byte.length);
				temp[data_byte.length] = 0x00;
				data_byte = temp;
			} else {
				if (data_byte.length != temp.length) {
					data_byte = temp;
				}
				break;
			}
		}
		//
		// 3、将MAB按8字节一组 分成n组 MAB1、MAB2、MAB3......MABn
		List<byte[]> maBytes = new ArrayList<>();
		for (int i = 0; i < data_byte.length / 8; i++) {
			byte[] temp1 = new byte[8];
			System.arraycopy(data_byte, i * 8, temp1, 0, 8);
			maBytes.add(temp1);
		}
		//
		// 4、用用8字节0与MAB1 异或得到MAB1-p
		byte[] mab1_p = bytesXOR(zero_byte, maBytes.get(0));
		System.out.println(getByteStr(mab1_p));

		byte[] mab1_c = DesUtils.encryptBy3DesCbc(mab1_p, key_byte);

		System.out.println(getByteStr(mab1_c));
		//
		// 5、用MAK（3DES）加密MAB1-p 得到MAB1-c
		//
		// 6、用MAB1-c 与 MAB2异或得到 MAB2-p
		//
		// 7、用MAK（3DES）加密MAB2-p 得到MAB2-c
		//
		// 8、用MAB2-c 与 MAB3异或得到 MAB3-p
		//
		// 9、用MAK（3DES）加密MAB3-p 得到MAB3-c
		//
		// 10、循环处理一直到最后一个分组异或加密后得到MABn-c ，MABn-c就是最终的MAC值
		return "";
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

	public static String getByteStr(byte[] in) {
		String re = "";
		for (byte b : in) {
			re += b + " ";
		}
		return re;
	}

}
