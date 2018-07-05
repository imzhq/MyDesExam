package com.hj.test;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

class MACCoder {

	/**
	 * 产生HmacMD2摘要算法的密钥
	 */
	public static byte[] initHmacMD2Key() throws NoSuchAlgorithmException {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacMD2");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacMd2摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacMD2(byte[] data, byte[] key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD2");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}

	/**
	 * 产生HmacMD4摘要算法的密钥
	 */
	public static byte[] initHmacMD4Key() throws NoSuchAlgorithmException {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacMD4");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacMD4摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacMD4(byte[] data, byte[] key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD4");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}

	/**
	 * 产生HmacSHA224摘要算法的密钥
	 */
	public static byte[] initHmacSHA224Key() throws NoSuchAlgorithmException {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacSHA224");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacSHA224摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacSHA224(byte[] data, byte[] key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA224");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}

}

public class MACTest {
	private static String key = "1C4A029B156E257A80572F6B4692CBCB";
	private static String data = "500800201803290958032018031515520104030109000008262306616310000202136230661631000020213=241122000000030";
	private static String reString;

	public static void main(String[] args) throws Exception {

		// byte[] keyHmacMD2 = MACCoder.initHmacMD2Key();
		System.out.println(MACCoder.encodeHmacMD2(data.getBytes(), key.getBytes()));

		byte[] keyHmacMD4 = MACCoder.initHmacMD4Key();
		System.out.println(MACCoder.encodeHmacMD4(data.getBytes(), key.getBytes()));

		byte[] keyHmacSHA224 = MACCoder.initHmacSHA224Key();
		System.out.println(MACCoder.encodeHmacSHA224(data.getBytes(), key.getBytes()));
	}
}