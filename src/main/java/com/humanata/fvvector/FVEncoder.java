package com.humanata.fvvector;

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
	 *  These are the powers to which the generator is raised to form the 
	 *  correct ordering of the roots of unity for the slot rotations to work
	 */
	public long generatorPowers[];
	

	
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
	public FVEncoder(FVParameters params)
	{
		this.params = params;
		this.generatorPowers = PolynomialUtils.CalculateMappingOfRoots(params.polynomialModulusExponent);
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
		UnivariatePolynomialZp64 tmp;
		for(int i = 0; i < values.length; i++)
		{
			tmp = params.ptPolyField.multiply(bases[i],values[i]);
			res = res.add(tmp);
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
	
	/**
	 * Returns the index of the encoder generator that swaps the rows of the vector
	 * when treating it as a N/2 x 2 array
	 * 
	 * @return index
	 */
	int interchangeIndex()
	{
		return generatorPowers.length/2;
	}

	/**
	 * Returns the index of the encoder generator that rotates the vector
	 * when treating it as a N/2 x 2 array
	 * 
	 * @param amount how many steps
	 * @return index 
	 */
	int leftRotateIndex(int amount)
	{
		int n2 = generatorPowers.length/2;
		return Math.floorMod(amount, n2);
	}

	/**
	 * Returns the index of the encoder generator that rotates the vector
	 * when treating it as a N/2 x 2 array
	 * 
	 * @param amount how many steps
	 * @return index 
	 */
	int rightRotateIndex(int amount)
	{
		int n2 = generatorPowers.length/2;
		return n2 - Math.floorMod(amount, n2);
	}
	
	/**
	 * Treat the polynomial as if it is encoding multiple values in a N/2 x 2 array
	 * Swap the values in the arrays
	 * 
	 * @param poly the polynomial to transform
	 * @return a new polynomial that has had its slots swapped
	 */
	UnivariatePolynomialZp64 interchangeSlots(UnivariatePolynomialZp64 poly)
	{
		int n2 = generatorPowers.length/2;
		return PolynomialUtils.coeffTransform(poly, generatorPowers[n2], generatorPowers.length);
	}

	/**
	 * Treat the polynomial as if it is encoding multiple values in a N/2 x 2 array
	 * Rotate the values according to the power of the generator stored in encoder
	 * 
	 * @param poly polynomial to transform
	 * @param index index of rotation to use
	 * @return
	 */
	UnivariatePolynomialZp64 transformSlots(UnivariatePolynomialZp64 poly, int index)
	{
		if(index <= 0)
			return poly.copy();
		
		return PolynomialUtils.coeffTransform(poly, generatorPowers[index], generatorPowers.length);
	}

	
	/**
	 * Treat the polynomial as if it is encoding multiple values in a N/2 x 2 array
	 * Rotate the values in the 2 vectors to the left some number of slots
	 * 
	 * @param poly polynomial to rotate
	 * @param slots number of slots to rotate
	 * @return
	 */
	UnivariatePolynomialZp64 rotateLeft(UnivariatePolynomialZp64 poly, int slots)
	{
		if(slots == 0)
			return poly.copy();
		
		int n2 = generatorPowers.length/2;
		int aslots = Math.floorMod(slots, n2);
		return PolynomialUtils.coeffTransform(poly, generatorPowers[aslots], generatorPowers.length);
	}

	/**
	 * Treat the polynomial as if it is encoding multiple values in a N/2 x 2 array
	 * Rotate the values in the 2 vectors to the right some number of slots
	 * 
	 * @param poly polynomial to rotate
	 * @param slots number of slots to rotate
	 * @return
	 */	UnivariatePolynomialZp64 rotateRight(UnivariatePolynomialZp64 poly, int slots)
	{
		if(slots == 0)
			return poly.copy();

		int n2 = generatorPowers.length/2;
		int aslots = Math.floorMod(slots, n2);
		return PolynomialUtils.coeffTransform(poly, generatorPowers[n2 - aslots], generatorPowers.length);
	}
	
}
