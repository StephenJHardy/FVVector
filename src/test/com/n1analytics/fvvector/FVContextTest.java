package com.n1analytics.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

import com.n1analytics.fvvector.FVParameters.SecurityParam;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

class FVContextTest {

	@Test
	public void testCalculateRootsOfUnity() throws Exception {
		long roots[] = FVContext.CalculateRootsOfUnity(16L, 97L);
		assertEquals(roots[0], 19L); // Calculated independently
	}

	@Test
	public void testCalculateBasisFunctions() throws Exception {
		long n = 16;
		long t = 97;
		long roots[] = FVContext.CalculateRootsOfUnity(n, t);
		UnivariatePolynomialZp64 bases[] = FVContext.CalculateBasisFunctions(n, t, roots);
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

	void AssertSmallPoly(UnivariatePolynomialZp64 sp)
	{
		long mo = 0, ze = 0, po = 0;
		for(int i= 0; i < sp.degree() + 1; i++)
		{
			long val = sp.get(i);
			
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
		double boundExpectedDeviation = Math.exp(1.0 + 0.6 * Math.log((double)sp.degree()+1));
		assertTrue(Math.abs(mo - po) < boundExpectedDeviation);
		assertTrue(Math.abs(ze - po) < boundExpectedDeviation);
		assertTrue(Math.abs(mo - ze) < boundExpectedDeviation);
	}
	
	@Test
	public void testGenerateSmallPolynomial() throws Exception {
		long n = 16;
		long t = 97;
		UnivariatePolynomialZp64 sp = FVContext.generateSmallPolynomial(n, t);
		assertEquals(sp.coefficientRingCardinality().longValue(), t);
		assertEquals(sp.degree(), (int)n-1);		
		AssertSmallPoly(sp);
	}
	


	@Test
	public void testGenerateUniformPolynomial() throws Exception {
		long n = 16;
		long t = 97;
		UnivariatePolynomialZp64 sp = FVContext.generateUniformPolynomial(n, t);
		assertEquals(sp.coefficientRingCardinality().longValue(), t);
		assertEquals(sp.degree(), n-1);		
		// not testing for uniformity here...
	}
	
	
	
	@Test
	public void testFVPolyGenerator() throws Exception {
		FVParameters ps = FVParameters.FVParamsN1024S128;
		FVContext pg = new FVContext(ps);
		
		for(int i = 0; i < ps.polynomialModulusExponent; i++)
		{
			for(int j = 0; j < ps.polynomialModulusExponent; j++)
			{
				long val = pg.bases[i].evaluate(pg.rootsOfUnity[j]);
				if(i==j)
					assertEquals(val,1L); // bases should evaluate to a delta function
				else
					assertEquals(val,0L);
			}
		}
		
		UnivariatePolynomialZp64 sp = pg.generateSmallPTPolynomial();
		AssertSmallPoly(sp);

		UnivariatePolynomialZp64 sp3 = pg.generaateUniformCTPolynomial();
		assertEquals(sp3.degree(), ps.polynomialModulusExponent-1);
		assertEquals(sp3.coefficientRingCardinality().longValue(), ps.coefficientModulus);
		
		UnivariatePolynomialZp64 sp2 = pg.generateNoiseCTPolynomial();
		assertEquals(sp2.degree(), ps.polynomialModulusExponent-1);
		assertEquals(sp2.coefficientRingCardinality().longValue(), ps.coefficientModulus);
	}

	@Test
	public void testGenerateNoisePolynomial() throws Exception {
		long n = 32768L;
		long t = 101L;
		UnivariatePolynomialZp64 sp = FVContext.generateNoisePolynomial(n, t, 3.19, 9.4 * 3.19);
		assertEquals(sp.degree(), (int)n - 1);
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
		
		assertThrows(IllegalArgumentException.class, () -> {  FVContext.generateNoisePolynomial(n, t, -3.19, 9.4 * 3.19); });
		assertThrows(IllegalArgumentException.class, () -> {  FVContext.generateNoisePolynomial(n, t, 3.19, 9.4 * 0); });

		
	}
}
