package com.n1analytics.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

import com.n1analytics.fvvector.FVParameters.SecurityParam;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

class FVParametersTest {

	@Test
	void testFVParameters() {
		FVParameters params = FVParameters.FVParamsN1024S128;
		try
		{
			params.CheckParameterConsistency(SecurityParam.BITS_128);
		} catch (IllegalArgumentException e)
		{
			fail("FVParameters");
		}
		// 128 bit should not pass the 192 bit security test
		assertThrows(IllegalArgumentException.class, () -> { params.CheckParameterConsistency(SecurityParam.BITS_192); });
		
		// bad arguments tests
		assertThrows(IllegalArgumentException.class, () -> {  new FVParameters(SecurityParam.BITS_128, -1L, 536839176L, 520193L, FVParameters.defaultNoiseSD); });

		assertThrows(IllegalArgumentException.class, () -> { new FVParameters(SecurityParam.BITS_128, 65536L, 536839176L, 520193L, FVParameters.defaultNoiseSD); });

		assertThrows(IllegalArgumentException.class, () -> { new FVParameters(SecurityParam.BITS_128, 1023L, 536839176L, 520193L, FVParameters.defaultNoiseSD); });
		
		assertThrows(IllegalArgumentException.class, () -> { new FVParameters(SecurityParam.BITS_128, 1024L, -1L, 520193L, FVParameters.defaultNoiseSD); });
		
		assertThrows(IllegalArgumentException.class, () -> { new FVParameters(SecurityParam.BITS_128, 1024L, Long.MAX_VALUE, 520193L, FVParameters.defaultNoiseSD); });
		
		assertThrows(IllegalArgumentException.class, () -> { new FVParameters(SecurityParam.BITS_128, 1024L, 536839176L, 520192L, FVParameters.defaultNoiseSD); });
		
		assertThrows(IllegalArgumentException.class, () -> { new FVParameters(SecurityParam.BITS_128, 1024L, 536839176L, -1L, FVParameters.defaultNoiseSD); });
		
		assertThrows(IllegalArgumentException.class, () -> { new FVParameters(SecurityParam.BITS_128, 1024L, 536839176L, Long.MAX_VALUE, FVParameters.defaultNoiseSD); });

		assertThrows(IllegalArgumentException.class, () -> {  new FVParameters(SecurityParam.BITS_128, 1024L, 536839175L, 520193L, FVParameters.defaultNoiseSD); });

		assertThrows(IllegalArgumentException.class, () -> { new FVParameters(SecurityParam.BITS_128, 1024L, 1073542130L, 1062913L, FVParameters.defaultNoiseSD); });

	}

	@Test
	public void testGenerateCongruentPrime() throws Exception {
		
		long cp = FVParameters.Generate2NCongruentPrime(29, 1024, 1);
		BigInteger lcp = BigInteger.valueOf(cp);
		assertTrue(lcp.isProbablePrime(100));
		assertEquals(lcp.bitLength(), 29);
		assertEquals(lcp.mod(BigInteger.valueOf(1024)).intValue(),1);
		
		assertThrows(ArithmeticException.class, () ->
		{
			FVParameters.Generate2NCongruentPrime(62, 1024, 1);
		} );
		assertThrows(ArithmeticException.class, () ->
		{
			FVParameters.Generate2NCongruentPrime(0, 1024, 1);
		} );
		assertThrows(ArithmeticException.class, () ->
		{
			FVParameters.Generate2NCongruentPrime(61, 0, 1);
		} );
		assertThrows(ArithmeticException.class, () ->
		{
			FVParameters.Generate2NCongruentPrime(61, -1, 1);
		} );

		
	}

	@Test
	public void testGenerateParameterSet() throws Exception {
		
		FVParameters.generateParameterSet(SecurityParam.BITS_128, 1024L, 16, 13);
		FVParameters.generateParameterSet(SecurityParam.BITS_192, 1024L, 14, 5);
		FVParameters.generateParameterSet(SecurityParam.BITS_128, 2048L, 16, 40);

		assertThrows(IllegalArgumentException.class, () -> { FVParameters.generateParameterSet(SecurityParam.BITS_128, 0L, 19, 10); });
		assertThrows(IllegalArgumentException.class, () -> { FVParameters.generateParameterSet(SecurityParam.BITS_128, 65536L, 19, 10); });
		assertThrows(IllegalArgumentException.class, () -> { FVParameters.generateParameterSet(SecurityParam.BITS_128, 1434L, 19, 10); });
		
		assertThrows(IllegalArgumentException.class, () -> { FVParameters.generateParameterSet(SecurityParam.BITS_128, 1024L, -1, 10); });
		assertThrows(IllegalArgumentException.class, () -> { FVParameters.generateParameterSet(SecurityParam.BITS_192, 0L, 19, 10); });
		assertThrows(IllegalArgumentException.class, () -> { FVParameters.generateParameterSet(SecurityParam.BITS_128, 1024L, 19, 19); });		
		
		assertThrows(RuntimeException.class, () -> { FVParameters.generateParameterSet(SecurityParam.BITS_192, 1024L, 10, 9); });		
		
	}
	
	@Test
	public void testGeneratePolynomials() throws Exception {
		FVParameters ps = FVParameters.FVParamsN1024S128;
		UnivariatePolynomialZp64 sp0 = ps.generateSmallPTPolynomial();
		assertTrue(sp0.degree() <= ps.polynomialModulusExponent-1);
		assertEquals(sp0.coefficientRingCardinality().longValue(), ps.plainTextModulus);
		
		UnivariatePolynomialZp64 sp1 = ps.generateSmallCTPolynomial();
		assertTrue(sp1.degree() <= ps.polynomialModulusExponent-1);
		assertEquals(sp1.coefficientRingCardinality().longValue(), ps.coefficientModulus);
				
		UnivariatePolynomialZp64 sp3 = ps.generaateUniformCTPolynomial();
		assertTrue(sp3.degree() <= ps.polynomialModulusExponent-1);
		assertEquals(sp3.coefficientRingCardinality().longValue(), ps.coefficientModulus);
		
		UnivariatePolynomialZp64 sp2 = ps.generateNoiseCTPolynomial();
		assertTrue(sp2.degree() <= ps.polynomialModulusExponent-1);
		assertEquals(sp2.coefficientRingCardinality().longValue(), ps.coefficientModulus);

	}

}
