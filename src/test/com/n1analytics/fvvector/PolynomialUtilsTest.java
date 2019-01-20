package com.n1analytics.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

class PolynomialUtilsTest {

	@Test
	public void testCalculateRootsOfUnity() throws Exception {
		long roots[] = PolynomialUtils.CalculateRootsOfUnity(16L, 97L);
		assertEquals(roots[0], 19L); // Calculated independently
	}

	@Test
	public void testCalculateBasisFunctions() throws Exception {
		long n = 16;
		long t = 97;
		long roots[] = PolynomialUtils.CalculateRootsOfUnity(n, t);
		UnivariatePolynomialZp64 bases[] = PolynomialUtils.CalculateBasisFunctions(n, t, roots);
		for(int i = 0; i < n; i++)
		{
			for(int j = 0; j < n; j++)
			{
				long val = bases[i].evaluate(roots[j]);
				if(i==j)
					assertEquals(val,1L); // bases should evaluate to a delta function
				else
					assertEquals(val,0L);
			}
		}
	}
	void AssertSmallPoly(long n, UnivariatePolynomialZp64 sp)
	{
		long mo = 0, ze = 0, po = 0;
		for(int i= 0; i < n; i++)
		{
			
			long val = 0L;
			if(i <= sp.degree())
				val = sp.get(i);  // high order coefficients might be zero
			
			if(val==sp.ring.modulus(-1L)) mo++;
			if(val==sp.ring.modulus(0L)) ze++;
			if(val==sp.ring.modulus(1L)) po++;	

			assertTrue((val == sp.ring.modulus(-1L)) || 
					(val == sp.ring.modulus(0L)) ||
					(val == sp.ring.modulus(1L))
					);
		}

		// should be roughly uniform distribution - heuristic below for how big a divergence should happen
		// based on powerlaw scaling of outlier distribution. Bound should only be violated exponentially rarely
		double boundExpectedDeviation = Math.exp(1.0 + 0.6 * Math.log((double)n));
		assertTrue(Math.abs(mo - po) < boundExpectedDeviation);
		assertTrue(Math.abs(ze - po) < boundExpectedDeviation);
		assertTrue(Math.abs(mo - ze) < boundExpectedDeviation);
	}

	long maxAbsCoeff(long t, UnivariatePolynomialZp64 sp)
	{
		long maxv = 0L;
		long t2 = t/2;
		for(int i = 0; i < sp.degree(); i++)
		{
			long v = sp.get(i);
			if(v > t2) v -= t;
			v = Math.abs(v);
			if(v > maxv)
				maxv = v;
		}
		return maxv;
	}
	
	@Test
	public void testGenerateSmallPolynomial() throws Exception {
		long n = 16;
		long t = 97;
		UnivariatePolynomialZp64 sp = PolynomialUtils.generateSmallPolynomial(n, t);
		assertEquals(sp.coefficientRingCardinality().longValue(), t);
		assertTrue(sp.degree() <= (int)n-1); // coefficients for high orders may be zero		
		AssertSmallPoly(n, sp);
	}
	


	@Test
	public void testGenerateUniformPolynomial() throws Exception {
		long n = FVParameters.FVParamsN2048S128.maxPolynomialExponent;
		long t = FVParameters.FVParamsN2048S128.coefficientModulus; // use a bigger t to make is larger than an int
		UnivariatePolynomialZp64 sp = PolynomialUtils.generateUniformPolynomial(n, t);
		assertEquals(sp.coefficientRingCardinality().longValue(), t);
		assertEquals(sp.degree(), n-1);		 // 1/97 this will fail if top coefficient is zero
		// not testing for uniformity here...
	}
	
	
	
	@Test
	public void testFVPolynomialUtil() throws Exception {
		FVParameters ps = FVParameters.FVParamsN1024S128;
		long rootsOfUnity[] = PolynomialUtils.CalculateRootsOfUnity(ps.polynomialModulusExponent, ps.plainTextModulus);
		UnivariatePolynomialZp64 bases[] = PolynomialUtils.CalculateBasisFunctions(ps.polynomialModulusExponent, ps.plainTextModulus, rootsOfUnity);
		
		for(int i = 0; i < ps.polynomialModulusExponent; i++)
		{
			for(int j = 0; j < ps.polynomialModulusExponent; j++)
			{
				long val = bases[i].evaluate(rootsOfUnity[j]);
				if(i==j)
					assertEquals(val,1L); // bases should evaluate to a delta function
				else
					assertEquals(val,0L);
			}
		}
		
		UnivariatePolynomialZp64 sp = PolynomialUtils.generateSmallPolynomial(ps.polynomialModulusExponent, ps.plainTextModulus);;
		AssertSmallPoly(ps.polynomialModulusExponent, sp);
	}

	@Test
	public void testGenerateNoisePolynomial() throws Exception {
		long n = 32768L;
		long t = 101L;
		UnivariatePolynomialZp64 sp = PolynomialUtils.generateNoisePolynomial(n, t, 3.19, 9.4 * 3.19);
		assertTrue(sp.degree() < (int)n);
		int countzero = 0, countone = 0, countminusone = 0;
		for(int i = 0; i < n; i++)
		{
			long l = sp.get(i);
			if(l == sp.ring.modulus(-1L)) countminusone++;
			else if(l == sp.ring.modulus(1L)) countone++;
			else if(l == sp.ring.modulus(0L)) countzero++;
		}
		double rat = (double)countzero / (double)(countone + countminusone);
		assertTrue(rat > 0.45 && rat < 0.6); // reasonable ratio between -1 or -1 and 0
		double rat2 = Math.abs((double)(countone - countminusone))/(double)countzero;
		assertTrue(rat2 < 0.1); // not too much variation between -1 and +1
		
		assertThrows(IllegalArgumentException.class, () -> {  PolynomialUtils.generateNoisePolynomial(n, t, -3.19, 9.4 * 3.19); });
		assertThrows(IllegalArgumentException.class, () -> {  PolynomialUtils.generateNoisePolynomial(n, t, 3.19, 9.4 * 0); });

		assertTrue(maxAbsCoeff(t,sp) < 30L);
		
	}
}
