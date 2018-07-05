package com.hj.test;

import java.io.PrintStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class ISO9797Alg3MacTest {
	static byte[] keyBytes = Hex.decode("1C4A029B156E257A80572F6B4692CBCB");

	static byte[] input1 = MacUtil.bcd2Bcd(
			"500800201803290958032018031515520104030109000008262306616310000202136230661631000020213=241122000000030"
					.getBytes());

	static byte[] output1 = Hex.decode("BC4458AF");

	public ISO9797Alg3MacTest() {
	}

	public static void performTest() {
		KeyParameter key = new KeyParameter(MacUtil.bcd2Bcd(keyBytes));
		BlockCipher cipher = new DESEngine();
		Mac mac = new ISO9797Alg3Mac(cipher);

		//
		// standard DAC - zero IV
		//
		mac.init(key);

		mac.update(MacUtil.bcd2Bcd(input1), 0, input1.length);

		byte[] out = new byte[8];

		mac.doFinal(out, 0);

		if (!areEqual(out, output1)) {
			System.out.println(
					"Failed - expected " + new String(Hex.encode(output1)) + " got " + new String(Hex.encode(out)));
		}

		//
		// reset
		//
		mac.reset();

		mac.init(key);

		for (int i = 0; i != input1.length / 2; i++) {
			mac.update(input1[i]);
		}

		mac.update(input1, input1.length / 2, input1.length - (input1.length / 2));

		mac.doFinal(out, 0);

		System.out.println(bytesToHex(out));

		if (!areEqual(out, output1)) {
			System.out.println("Reset failed - expected " + new String(Hex.encode(output1)) + " got "
					+ new String(Hex.encode(out)));
		}

		testMacWithIv();
	}

	public static String bytesToHex(byte[] data) {
		if (data == null) {
			return null;
		} else {
			int len = data.length;
			String str = "";
			for (int i = 0; i < len; i++) {
				if ((data[i] & 0xFF) < 16)
					str = str + "0" + java.lang.Integer.toHexString(data[i] & 0xFF);
				else
					str = str + java.lang.Integer.toHexString(data[i] & 0xFF);
			}
			return str.toUpperCase();
		}
	}

	private static void testMacWithIv() {
		byte[] inputData = new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 };
		byte[] key = new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 };
		byte[] zeroIv = new byte[8];
		byte[] nonZeroIv = new byte[] { 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4 };

		KeyParameter simpleParameter = new KeyParameter(key);
		ParametersWithIV zeroIvParameter = new ParametersWithIV(new KeyParameter(key), zeroIv);

		ISO9797Alg3Mac mac1 = new ISO9797Alg3Mac(new DESEngine(), new ISO7816d4Padding());

		// we calculate a reference MAC with a null IV
		mac1.init(simpleParameter);
		mac1.update(inputData, 0, inputData.length);
		byte[] output1 = new byte[mac1.getMacSize()];
		mac1.doFinal(output1, 0);

		// we then check that passing a vector of 0s is the same as not using any IV
		ISO9797Alg3Mac mac2 = new ISO9797Alg3Mac(new DESEngine(), new ISO7816d4Padding());
		mac2.init(zeroIvParameter);
		mac2.update(inputData, 0, inputData.length);
		byte[] output2 = new byte[mac2.getMacSize()];
		mac2.doFinal(output2, 0);
		if (!Arrays.areEqual(output1, output2)) {
			// fail("zero IV test failed");
		}

		// and then check that a non zero IV parameter produces a different results.
		ParametersWithIV nonZeroIvParameter = new ParametersWithIV(new KeyParameter(key), nonZeroIv);
		mac2 = new ISO9797Alg3Mac(new DESEngine(), new ISO7816d4Padding());
		mac2.init(nonZeroIvParameter);
		mac2.update(inputData, 0, inputData.length);
		output2 = new byte[mac2.getMacSize()];
		mac2.doFinal(output2, 0);
		if (Arrays.areEqual(output1, output2)) {
			// fail("non-zero IV test failed");
		}
	}

	public String getName() {
		return "ISO9797Alg3Mac";
	}

	public static void main(String[] args) {
		performTest();
	}

	// private TestResult success() {
	// return SimpleTestResult.successful(this, "Okay");
	// }
	//
	// protected void fail(String message) {
	// throw new TestFailedException(SimpleTestResult.failed(this, message));
	// }
	//
	// protected void isTrue(boolean value) {
	// if (!value) {
	// throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
	// }
	// }
	//
	// protected void isTrue(String message, boolean value) {
	// if (!value) {
	// throw new TestFailedException(SimpleTestResult.failed(this, message));
	// }
	// }
	//
	// protected void isEquals(Object a, Object b) {
	// if (!a.equals(b)) {
	// throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
	// }
	// }
	//
	// protected void isEquals(int a, int b) {
	// if (a != b) {
	// throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
	// }
	// }
	//
	// protected void isEquals(long a, long b) {
	// if (a != b) {
	// throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
	// }
	// }
	//
	// protected void isEquals(String message, boolean a, boolean b) {
	// if (a != b) {
	// throw new TestFailedException(SimpleTestResult.failed(this, message));
	// }
	// }
	//
	// protected void isEquals(String message, long a, long b) {
	// if (a != b) {
	// throw new TestFailedException(SimpleTestResult.failed(this, message));
	// }
	// }

	// protected void isEquals(String message, Object a, Object b) {
	// if (a == null && b == null) {
	// return;
	// } else if (a == null) {
	// throw new TestFailedException(SimpleTestResult.failed(this, message));
	// } else if (b == null) {
	// throw new TestFailedException(SimpleTestResult.failed(this, message));
	// }
	//
	// if (!a.equals(b)) {
	// throw new TestFailedException(SimpleTestResult.failed(this, message));
	// }
	// }

	protected boolean areEqual(byte[][] left, byte[][] right) {
		if (left == null && right == null) {
			return true;
		} else if (left == null || right == null) {
			return false;
		}

		if (left.length != right.length) {
			return false;
		}

		for (int t = 0; t < left.length; t++) {
			if (areEqual(left[t], right[t])) {
				continue;
			}
			return false;
		}

		return true;
	}

	// protected void fail(String message, Throwable throwable) {
	// throw new TestFailedException(SimpleTestResult.failed(this, message,
	// throwable));
	// }
	//
	// protected void fail(String message, Object expected, Object found) {
	// throw new TestFailedException(SimpleTestResult.failed(this, message,
	// expected, found));
	// }

	protected static boolean areEqual(byte[] a, byte[] b) {
		return Arrays.areEqual(a, b);
	}

	// public TestResult perform() {
	// try {
	// performTest();
	// return success();
	// } catch (TestFailedException e) {
	// return e.getResult();
	// } catch (Exception e) {
	// return SimpleTestResult.failed(this, "Exception: " + e, e);
	// }
	// }
	//
	// protected static void runTest(Test test) {
	// runTest(test, System.out);
	// }

	protected static void runTest(Test test, PrintStream out) {
		TestResult result = test.perform();

		out.println(result.toString());
		if (result.getException() != null) {
			result.getException().printStackTrace(out);
		}
	}

	// public abstract void performTest() throws Exception;
}
