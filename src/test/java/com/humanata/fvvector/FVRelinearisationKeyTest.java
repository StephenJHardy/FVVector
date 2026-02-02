package com.humanata.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

class FVRelinearisationKeyTest {

	@Test
	void testFVRelinearisationKey() {
		FVParameters ps = FVParameters.FVParamsN1024S128insecure;
		FVPrivateKey  pk = new FVPrivateKey(ps);
		FVRelinearisationKey rk = new FVRelinearisationKey(pk);
		
		assertEquals(rk.polys0.size(), (int)Math.floor(Math.log(ps.coefficientModulus)/Math.log(ps.decompositionBase))+1);
		assertEquals(rk.polys1.size(), (int)Math.floor(Math.log(ps.coefficientModulus)/Math.log(ps.decompositionBase))+1);
		assertEquals(rk.polys0.get(0).coefficientRingCardinality().longValue(), ps.coefficientModulus);
		assertEquals(rk.polys1.get(0).coefficientRingCardinality().longValue(), ps.coefficientModulus);

		// now show we can reconstruct the square of the private key from the decomposition
		// in the relinearisation key - need to use a no-noise insecure set of parameters for this
		// to work
		UnivariatePolynomialZp64 sec2 = ps.ctPolyField.multiply(pk.key(), pk.key());
		
		for(int i = 0; i < rk.polys0.size(); i++)
		{
			UnivariatePolynomialZp64 sum = 
						ps.ctPolyField.add(rk.polys0.get(i),
								ps.ctPolyField.multiply(rk.polys1.get(i), pk.key())
						);

			for(int j = 0; j < sec2.degree(); j++)
			{
				assertEquals(sum.get(j), sec2.get(j));
			}

			sec2 = ps.ctPolyField.multiply(sec2, ps.decompositionBase);
		}

	}

}
