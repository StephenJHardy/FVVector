package com.n1analytics.fvvector;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

public class FVRotationKeyTest {

	@Test
	public void testFVRotationKey() throws Exception {
		FVParameters ps = FVParameters.FVParamsN1024S128insecure;
		FVPrivateKey  pk = new FVPrivateKey(ps);
		FVEncoder encoder = new FVEncoder(ps);
		FVRotationKey rk = new FVRotationKey(pk, encoder);

		// We show can reconstruct the difference between the private key and the 
		// rotated private key from the decomposition
		// in the rotation key - need to use a no-noise insecure set of parameters for this
		// to work
		
		for(int k = 0; k < rk.keys0.size(); k++)
		{
			UnivariatePolynomialZp64 transpk = encoder.transformSlots(pk.key(), k);
			UnivariatePolynomialZp64 sub2 = ps.ctPolyField.subtract(transpk, pk.key());
						
			for(int i = 0; i < rk.keys0.get(k).size(); i++)
			{
				UnivariatePolynomialZp64 sum = 
							ps.ctPolyField.add(rk.keys0.get(k).get(i),
									ps.ctPolyField.multiply(rk.keys1.get(k).get(i), pk.key())
							);

				for(int j = 0; j < sub2.degree(); j++)
				{
					assertEquals(sum.get(j), sub2.get(j));
				}

				sub2 = ps.ctPolyField.multiply(sub2, ps.decompositionBase);
			}


		}

	
	
	}

}
