package com.humanata.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class FVPublicKeyTest {

	@Test
	void test() {
		FVParameters ps = FVParameters.FVParamsN1024S128;
		FVPrivateKey  pk = new FVPrivateKey(ps);
		FVPublicKey pub = new FVPublicKey(pk);
		
		assertEquals(pub.e0().degree(), ps.polynomialModulusExponent-1);
		assertEquals(pub.e0().coefficientRingCardinality().longValue(), ps.coefficientModulus);
		assertEquals(pub.e1().degree(), ps.polynomialModulusExponent-1);
		assertEquals(pub.e1().coefficientRingCardinality().longValue(), ps.coefficientModulus);
	}

}
