/**
 * 
 */

package com.humanata.fvvector;


import static cc.redberry.rings.Rings.GF;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import cc.redberry.rings.bigint.BigInteger;
import cc.redberry.rings.IntegersZp64;
import cc.redberry.rings.poly.FiniteField;
import cc.redberry.rings.poly.univar.UnivariatePolynomial;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/**
 * 
 * This class is used to construct a description of the parameters of the FV crypto system
 * that is being used.
 * 
 * There are some stringent limitations on the parameters at this time:
 * * only polynomials of the form X^(2^d)+1 are supported for some d
 * * 2^d is smaller or less that 32768
 * * the plainTextModulus must be smaller than 2^61 at this time
 * * the plainTextModulus must be a prime number and congruent to 1 (mod 2n)
 * * the coefficientModulus modulus must be smaller than 2^61 at this time
 * * the coefficientModulus must be an integer multiple of the plainTextModulus
 * 
 * Convenient choices for 1024 length vectors and 2048 length vectors at 128 bit
 * are available as static members FVParamsN1024S128 and FVParamsN2048S128
 * 
 * @author har991
 *
 */
public class FVParameters {

	public enum SecurityParam {
	    BITS_128, BITS_192 
	};
	
	public static final int maxCoefficientBits = Long.SIZE - 3;
	public static final long maxCoefficientModulus = (1L << maxCoefficientBits);
	public static final int maxPolynomialExponent = 32768;
	
    private static final Map<Long, Integer> polymodMaxBits128;
    static {
        Map<Long, Integer> aMap = new HashMap<Long, Integer>();
        aMap.put(1024L, 29);
        aMap.put(2048L, 56);
        aMap.put(4096L, 110);
        aMap.put(8192L, 219);
        aMap.put(16384L, 441);
        aMap.put(32768L, 885);
        polymodMaxBits128 = Collections.unmodifiableMap(aMap);
    }
    private static final Map<Long, Integer> polymodMaxBits192;
    static {
        Map<Long, Integer> aMap = new HashMap<Long, Integer>();
        aMap.put(1024L, 20);
        aMap.put(2048L, 39);
        aMap.put(4096L, 77);
        aMap.put(8192L, 153);
        aMap.put(16384L, 300);
        aMap.put(32768L, 600);
        polymodMaxBits192 = Collections.unmodifiableMap(aMap);
    }
	
   
    public static final double defaultNoiseSD = 3.19153824321146142351956847947505494780686905d; // 8.0 / Math.sqrt(2*Math.PI);

    /**
     * A conservative parameter set that gives 128 bits of security and 1024 vector size.
     * Has 16 bits for the plaintext, 29 for the ciphertext, giving q/t of 13106. Enough for encrypt/decrypt, but not enough for much arithmetic
     */
    public static final FVParameters FVParamsN1024S128  = new FVParameters(SecurityParam.BITS_128, 1024L, 536834866L, 40961L, defaultNoiseSD, 8); //16 bits in t, 29 bits in q

    /**
     * A conservative parameter set that gives 128 bits of security and 2048 vector size.
     * Has 32 bits for the plaintext, 56 for the ciphertext, giving q/t of 24 bits.
     */
    public static final FVParameters FVParamsN2048S128  = new FVParameters(SecurityParam.BITS_128, 2048L, 72057593221401751L, 4096172033L, defaultNoiseSD, 8); //19 bits in t, 29 bits in q
 
    /**
     * A conservative parameter set that gives 128 bits of security and 2048 vector size.
     * Has 16 bits for the plaintext, 40 for the ciphertext, giving q/t of 34 bits.
     */
    public static final FVParameters FVParamsN2048S128small  = new FVParameters(SecurityParam.BITS_128, 2048L, 72057594037920137L, 40961L, defaultNoiseSD, 8); //16 bits in t, 40 bits in q

     /** 
      * Some insecure parameters - with no noise added to the ciphertexts. Purely here for testing and @todo should be removed.
      */
    public static final FVParameters FVParamsN1024S128insecure  = new FVParameters(SecurityParam.BITS_128, 1024L, 536834866L, 40961L, 0.0000000001, 8); //16 bits in t, 29 bits in q
    public static final FVParameters FVParamsN2048S128insecure  = new FVParameters(SecurityParam.BITS_128, 2048L, 72057593221401751L, 4096172033L, 0.0000000001, 8); //19 bits in t, 29 bits in q
    
   
    
    
	long coefficientModulus;
	long plainTextModulus;
	long polynomialModulusExponent;
	double noiseStandardDeviation;
	long decompositionBase;
	long l;

	/**
	 *  The following members are defined for convenience. They allow the user to generate polynomials, apply modular arithmetic etc.
	 *  in the appropriate fields for the parameters contained in the class
	 */
	
	IntegersZp64 ptRing;   // plaintext ring - integers modulus plainTextModulus
	IntegersZp64 ctRing;   // ciphertext ring - integers modulus coefficientModulus
	UnivariatePolynomialZp64 ptQuotientPoly;  // the quotient poly = x^polynomialModulusExponent + 1 with coefficients from plaintext ring
	UnivariatePolynomialZp64 ctQuotientPoly;  // the quotient poly = x^polynomialModulusExponent + 1 with coefficients from ciphertext ring
	FiniteField<UnivariatePolynomialZp64> ptPolyField; // the Galois Field represented by polynomials with coefficients in the plaintext ring modolo the quotient poly
	FiniteField<UnivariatePolynomialZp64> ctPolyField; // the Galois Field represented by polynomials with coefficients in the ciphertext ring modolo the quotient poly
 	
	/**
	 * 
	 * Construct a parameter set for Fan Vercauterin for the given parameters that
	 * has the required security but maintains the constraints of this package.
	 * 
     * Constructs a parameter set that uses ternary private keys (i.e. <code>polyType=SIMPLE</code>).
     *
     * @param n            degree of the polynomial field (must be power of 2)
     * @param q            coefficient modulus for encrypted polynomials
     * @param t            coefficient modulus for plaintext polynomials
     * @param sigma        standard deviation of noise polynomials
     * @param decompBase   base into which coefficients of polynomials are decomposed for computation keys
     */
	public FVParameters(SecurityParam bos, long n, long q, long t, double sigma, long decompBase)
	{
		this.coefficientModulus = q;
		this.polynomialModulusExponent = n;
		this.plainTextModulus = t;
		this.noiseStandardDeviation = sigma;
		this.decompositionBase = decompBase;
		this.l = (long)Math.floor(Math.log(q)/Math.log(decompBase));
		CheckParameterConsistency(bos);
		ConstructPolynomialFields();
	}
	
	

	/**
	 * Checks the parameters stored in the class for consistency with the constraints on the 
	 * FV parameter set.
	 * 
	 * @param bos required security level to be satistified
	 */
	public void CheckParameterConsistency(SecurityParam bos)
	{
		if((plainTextModulus < 0) || (plainTextModulus > maxCoefficientModulus) ) 
			throw new IllegalArgumentException("Plaintext modulus out of range");
		if((polynomialModulusExponent < 0) || (polynomialModulusExponent > maxPolynomialExponent))
			throw new IllegalArgumentException("polynomialModulusExponent out of range");
		if((coefficientModulus < 0) || (coefficientModulus > maxCoefficientModulus))
			throw new IllegalArgumentException("coefficientModulus out of range");

		if(BigInteger.valueOf(polynomialModulusExponent).bitCount() != 1) 
			throw new IllegalArgumentException("polynomialModulusExponent not a power of 2");

		if(!Is2NCongruent(plainTextModulus,polynomialModulusExponent,1)) 
			throw new IllegalArgumentException("Plaintext modulus not congruent to 1 (mod 2 n)");
		
		if(Math.floorDiv(coefficientModulus , plainTextModulus) * plainTextModulus != coefficientModulus) 
			throw new IllegalArgumentException("plainTextModulus does not divide coefficientModulus ");

		if(bos == SecurityParam.BITS_128)
		{
			if(polymodMaxBits128.get(polynomialModulusExponent) < BigInteger.valueOf(coefficientModulus).bitLength())
				throw new IllegalArgumentException("coefficientModulus too large - insecure");	
		}
		else
		{
			if(polymodMaxBits192.get(polynomialModulusExponent) < BigInteger.valueOf(coefficientModulus).bitLength())
				throw new IllegalArgumentException("coefficientModulus too large - insecure");	
		}
		
		if(decompositionBase > coefficientModulus)
			throw new IllegalArgumentException("Decomposition base smaller than coefficient modulus");
		
		if(decompositionBase < 0)
			throw new IllegalArgumentException("Decomposition base must be positive");
			
	}
	
	/**
	 * Generates a set of parameters with a given number of bits in the plaintext, a given number of bits available for noise
	 * and check it matches the given security parameters
	 * 
	 * @param n    exponent of the polynomial modulus
	 * @param numBitsPT   number of bits in the plain text modulus
	 * @param numBitsOverhead  number of bits the coefficient modulus is larger than the plaintext modulus
	 * @param bos	required number of bits of security
	 * @return
	 * @throws IllegalArgumentException
	 */
	public static FVParameters generateParameterSet(SecurityParam bos, long n, int numBitsPT, int numBitsOverhead) throws IllegalArgumentException
	{
		if((n < 0) || (n > maxPolynomialExponent))
			throw new IllegalArgumentException("n out of range");
		if(BigInteger.valueOf(n).bitCount() != 1) 
			throw new IllegalArgumentException("n not a power of 2");

		if((numBitsPT <= 0) || (numBitsOverhead <= 0))
			throw new IllegalArgumentException("number of bits required to be greater than zero");

		
		int requiredBits = polymodMaxBits128.get(n);
		if(bos==SecurityParam.BITS_192)
			requiredBits = polymodMaxBits192.get(n);
		
		if(numBitsPT + numBitsOverhead > requiredBits)
		{
			throw new IllegalArgumentException("Too many bits required in coefficientModulus for required security level");
		}
		
		long t = generatePlainTextModulus(n, numBitsPT);
		long q = generateCoefficientModulus(t, numBitsPT + numBitsOverhead);
		return new FVParameters(bos, n, q, t,defaultNoiseSD, 8);
	}

	

	/**
	 * Generate a modulus for the plaintext polynomial coefficients. Must be prime, and congruent to 1 mod (2n)./
	 * Private method - assumed inputs are checked
	 * 
	 * @param n  order of polynomial
	 * @param numBitsPT number of bits required in the generated modulus
	 * @return a modulus that satisfies the requirements
	 */
	private static long generatePlainTextModulus(long n, int numBits) {
		// we do this by brute force search in absence of a cleverer method
		// TODO: examine whether there are cleverer methods
		long twon = 2 * n;
		long minSearch = 1L << (numBits - 1);
		long i = minSearch / twon;
		long i2 = (2L * minSearch) / twon;
		long val = 0L;
		while(i < i2)
		{
			val = twon * i + 1L;
			if(BigInteger.valueOf(val).isProbablePrime(30))
			{
				break;
			}	
			i++;
		}
		if(i == i2) 
			throw new RuntimeException("could not find prime of appropriate bit length");
		return val;
	}

	/**
	 * Generate a modulus for the encrypted polynomial space - must be an integer multiple of t
	 * @param t  plaintext modulus
	 * @param numBits  number of bits required
	 * @return modulus of the encrypted polynomial space
	 */
	private static long generateCoefficientModulus(long t, int numBits) {
		long maxValWithRequiredBits = (1L << numBits) - 1;
		return (maxValWithRequiredBits/t) * t;
	}


	/**
	 * Generate a prime number p that satisfies p (mod 2 n) == c (mod 2 n)
	 *  and where p has bitCount significant bits.
	 * 
	 * @param bitCount number of significant bits in returned element
	 * @param n modulus
	 * @param c returned number is equivalent to this mod 2n
	 * @return prime that satisfies the constraints
	 */
	public static long Generate2NCongruentPrime(int bitCount, long n, int c) throws ArithmeticException
	{
		if(bitCount > maxCoefficientBits) throw new ArithmeticException("BitCount requested too large");
		if(bitCount < 1) throw new ArithmeticException("BitCount requested too small");
		if(n < 1) throw new ArithmeticException("modulus requested zero or negative");
		
		SecureRandom srng = new SecureRandom();
		long result = 0L;
		BigInteger twon = BigInteger.valueOf(2*n);
		BigInteger cbi = BigInteger.valueOf(c);
		while(result == 0L)
		{
			BigInteger pPrime = BigInteger.probablePrime(bitCount, srng);
			BigInteger res = pPrime.subtract(cbi).mod(twon);
			if(res.intValue() == 0)
				result = pPrime.intValueExact();
		}
		return result;
	}
	
	/**
	 * Test that input v is congruent to c mod 2n
	 * 
	 * @param v    value
	 * @param n	   modulus n
	 * @param c    congruence
	 * @return	   boolean saying whether test is passed.
	 * @throws ArithmeticException
	 */
	public static boolean Is2NCongruent(long v, long n, int c) throws ArithmeticException
	{
		return BigInteger.valueOf(v - c).mod(BigInteger.valueOf(2*n)).intValue() == 0;
	}
	
	
	/**
	 *  Construct the object that represents polynomials in the plaintext and ciphertext spaces
	 */
	private void ConstructPolynomialFields() {
		long[] data = new long[(int)polynomialModulusExponent + 1];
		data[0] = 1L;
		data[(int)polynomialModulusExponent]=1L;

		this.ptQuotientPoly = UnivariatePolynomialZp64.create(plainTextModulus, data);
		this.ptPolyField = GF(ptQuotientPoly);
		this.ptRing = ptQuotientPoly.ring;
		this.ctQuotientPoly = UnivariatePolynomialZp64.create(coefficientModulus, data);
		this.ctPolyField = GF(ctQuotientPoly);		
		this.ctRing = ctQuotientPoly.ring;
		
	}

	
	/**
	 * Generates a polynomial in the plaintext space with "small" (-1,0,1) coefficients randomly
	 * distributed.
	 * 
	 * @return Polynomial with "small" coefficients
	 */
	UnivariatePolynomialZp64 generateSmallPTPolynomial()
	{
		return PolynomialUtils.generateSmallPolynomial(polynomialModulusExponent, plainTextModulus);
	}
	
	/**
	 * Generates a polynomial in the ciphertext space with "small" (-1,0,1) coefficients randomly
	 * distributed.
	 * 
	 * @return Polynomial with "small" coefficients
	 */
	UnivariatePolynomialZp64 generateSmallCTPolynomial()
	{
		return PolynomialUtils.generateSmallPolynomial(polynomialModulusExponent, coefficientModulus);
	}
	
	/**
	 * Generates a polynomial in the ciphertext space with uniform coefficients randomly
	 * distributed from 0 to coefficientModulus - 1.
	 * 
	 * @return Polynomial with uniform coefficients
	 */
	UnivariatePolynomialZp64  generaateUniformCTPolynomial()
	{
		return PolynomialUtils.generateUniformPolynomial(polynomialModulusExponent, coefficientModulus);
	}

	/**
	 * Generates a polynomial in the ciphertext space with  coefficients randomly
	 * distributed drawn from a discrete gaussian distribution with a standard deviation
	 * given by noiseStandardDeviation. Distribution is cutoff where probability of a 
	 * value is less than 2^-64.
	 * 
	 * @return Polynomial with noise coefficients
	 */
	UnivariatePolynomialZp64 generateNoiseCTPolynomial()
	{
		// 9.4 magic number in the following comes from the initial FV paper as a bound where < 2-64 chance of hitting an integer outside this range.
		return PolynomialUtils.generateNoisePolynomial(polynomialModulusExponent, coefficientModulus, noiseStandardDeviation, 9.4*noiseStandardDeviation);
	}

}
