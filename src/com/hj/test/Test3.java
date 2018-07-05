package com.hj.test;

import java.math.BigDecimal;
import java.math.RoundingMode;

public class Test3 {

	public static void main(String[] args) {

		BigDecimal num = new BigDecimal("11.01");
		System.out.println(Bd2LongStr(num));
	}

	public static String Bd2LongStr(BigDecimal num) {
		num = num.setScale(2, RoundingMode.HALF_DOWN);
		num = num.multiply(new BigDecimal("100.00"));
		return num.setScale(0, RoundingMode.HALF_DOWN).toString();
	}
}
