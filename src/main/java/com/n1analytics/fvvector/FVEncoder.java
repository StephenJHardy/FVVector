package com.n1analytics.fvvector;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/**
 * This class represents an encoder that takes an array of long values and produces a polynomial
 * with the values of the array in the slots of the polynomial. It can also decode a polynomial to
 * an array of longs. The parameters that are used for this process are specified in the constructor.
 * 
 */
public class FVEncoder {

	/**
	 *  The parameters for which the encoding is done.
	 */
	public FVParameters params;

	/**
	 *  The roots of unity for the ring of integers modulo params.plainTextModulus.
	 *  They are primes, p, where p^(2n) == 1, and there is no j<2n where p^(j) == 1.
	 *  There are n of these, where n = params.polynomialModulusExponent
	 */
	private long rootsOfUnity[];
	
	
	/**
	 *  The basis functions of the corresponding roots of unity. These are an orthonormal
	 *  set of functions that are one evaluated at their corresponding root, and zero
	 *  when evaluated at any other root. 
	 */
	private UnivariatePolynomialZp64 bases[];

	
	/**
	 * Create an encoder object that will convert between polynomials and arrays of longs
	 * according to the parameters supplied. This can take some time to execute as it calculates
	 * and caches some intermediate results relating to the parameters. 
	 * 
	 * @param params the set of parameters for the encoding mechanism
	 * 
	 */
	FVEncoder(FVParameters params)
	{
		this.params = params;
		this.rootsOfUnity = PolynomialUtils.CalculateRootsOfUnity(params.polynomialModulusExponent, params.plainTextModulus);
		this.bases = PolynomialUtils.CalculateBasisFunctions(params.polynomialModulusExponent, params.plainTextModulus, rootsOfUnity);
	}		
			
	
	/**
	 * Take an array of longs and encode into a polynomial according to the parameter scheme 
	 * 
	 * @param values Array of longs to be encoded, must be length params.polynomialModulusExponent
	 * @return Polynomial with values encoded in the slots
	 */
	UnivariatePolynomialZp64 encode(long[] values)
	{
		if(values.length != params.polynomialModulusExponent) throw new RuntimeException("incorrect size of array for encoding");
		
		UnivariatePolynomialZp64 res = UnivariatePolynomialZp64.zero(params.plainTextModulus);
		for(int i = 0; i < values.length; i++)
		{
			res = res.add(params.ptPolyField.multiply(bases[i],values[i]));
		}
		return res;
	}
	
	/**
	 * Take a polynomial and return an array of longs decoded from the slots
	 * 
	 * @param poly Polynomial to decode - should be consistent with the parameters of the encoder
	 * @return Array of longs of length params.polynomialModulusExponent
	 * 
	 */
	long[] decode(UnivariatePolynomialZp64 poly)
	{
		if( (poly.ring.modulus != params.plainTextModulus) || 
		    (poly.size() > params.polynomialModulusExponent) )
				throw new RuntimeException("incorrect polynomial parameters for decoding");
		
		long[] res = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < res.length; i++)
		{
			res[i] = poly.evaluate(rootsOfUnity[i]);
		}
		return res;
	}
	
}
