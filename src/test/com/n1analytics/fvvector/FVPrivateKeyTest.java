package com.n1analytics.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class FVPrivateKeyTest {

	@Test
	void testFVPrivateKey() {
		FVParameters ps = FVParameters.FVParamsN1024S128;
		FVPrivateKey  pk = new FVPrivateKey(ps);
		
		//smallness of the private key poly is tested in polynomialutilstest
		assertTrue( pk.key().degree() > 0 ); 
		assertEquals(pk.key().coefficientRingCardinality().longValue(), ps.coefficientModulus);

	}

}
