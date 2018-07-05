package com.hj.test.one;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class DesUtils {
	private final static String DES = "DES";
	private final static String CIPHER_ALGORITHM = "DES/ECB/NoPadding";

	public static final byte[] ZERO_IVC = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };

	/**
	 * 加密
	 * 
	 * @param src
	 *            数据源
	 * @param key
	 *            密钥，长度必须是8的倍数
	 * @return 返回加密后的数据
	 */
	public static byte[] encrypt(byte[] src, byte[] key) {
		SecureRandom sr = new SecureRandom();
		try {
			DESKeySpec dks = new DESKeySpec(key);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
			SecretKey securekey = keyFactory.generateSecret(dks);
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);
			return cipher.doFinal(src);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * des的cbc模式加密算法
	 * 
	 * @param content
	 *            待加密数据
	 * @param key
	 *            密钥
	 * @return 加密结果
	 * @throws GeneralSecurityException
	 */
	public static byte[] encryptByDesCbc(byte[] content, byte[] key) throws GeneralSecurityException {
		return encryptByDesCbc(content, key, ZERO_IVC);
	}

	/**
	 * des的cbc模式加密算法
	 * 
	 * @param content
	 *            待加密数据
	 * @param key
	 *            加密密钥
	 * @return 加密结果
	 * @throws GeneralSecurityException
	 */
	public static byte[] encryptByDesCbc(byte[] content, byte[] key, byte[] icv) throws GeneralSecurityException {
		SecureRandom sr = new SecureRandom();
		DESKeySpec dks = new DESKeySpec(key);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
		SecretKey secretKey = keyFactory.generateSecret(dks);
		Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
		IvParameterSpec iv = new IvParameterSpec(icv);

		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv, sr);

		return cipher.doFinal(content);
	}

	/**
	 * 生成密钥
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] initKey() throws NoSuchAlgorithmException {
		KeyGenerator kg = KeyGenerator.getInstance(DES);
		kg.init(16);
		SecretKey secretKey = kg.generateKey();
		return secretKey.getEncoded();
	}

	/**
	 * 解密
	 * 
	 * @param src
	 *            数据源
	 * @param key
	 *            密钥，长度必须是8的倍数
	 * @return 返回解密后的原始数据
	 */
	public static byte[] decrypt(byte[] src, byte[] key) {
		SecureRandom sr = new SecureRandom();
		try {
			DESKeySpec dks = new DESKeySpec(key);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
			SecretKey securekey = keyFactory.generateSecret(dks);
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, securekey, sr);
			return cipher.doFinal(src);
		} catch (Exception e) {
		}
		return null;
	}
}
