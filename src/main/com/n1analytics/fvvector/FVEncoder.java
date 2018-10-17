package com.n1analytics.fvvector;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

public class FVEncoder {

	FVContext pgen;

	FVEncoder(FVContext pgen)
	{
		this.pgen = pgen;
	}		
			
	UnivariatePolynomialZp64 encode(long[] values)
	{
		if(values.length != pgen.params.polynomialModulusExponent) throw new RuntimeException("incorrect size of array for encoding");
		
		UnivariatePolynomialZp64 res = UnivariatePolynomialZp64.zero(pgen.params.plainTextModulus);
		for(int i = 0; i < values.length; i++)
		{
			res = res.add(pgen.ptPolyField.multiply(pgen.bases[i],values[i]));
		}
		return res;
	}
	
	long[] decode(UnivariatePolynomialZp64 poly)
	{
		long[] res = new long[(int)pgen.params.polynomialModulusExponent];
		for(int i = 0; i < res.length; i++)
		{
			res[i] = poly.evaluate(pgen.rootsOfUnity[i]);
		}
		return res;
	}
	
}
