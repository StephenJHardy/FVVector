/**
 * 
 */

package com.n1analytics.fvvector;


import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


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
	
    public static final double defaultNoiseSD = 8.0 / Math.sqrt(2*Math.PI);

    /**
     * A conservative parameter set that gives 128 bits of security and 1024 vector size.
     * Has 19 bits for the plaintext, 29 for the ciphertext, giving q/t of 1032.
     */
    public static final FVParameters FVParamsN1024S128  = new FVParameters(SecurityParam.BITS_128, 1024L, 536839176L, 520193L, defaultNoiseSD); //19 bits in t, 29 bits in q

    /**
     * A conservative parameter set that gives 128 bits of security and 2048 vector size.
     * Has 32 bits for the plaintext, 56 for the ciphertext, giving q/t of 24 bits.
     */
    public static final FVParameters FVParamsN2048S128  = new FVParameters(SecurityParam.BITS_128, 2048L, 72057593221401751L, 4096172033L, defaultNoiseSD); //19 bits in t, 29 bits in q
    
	long coefficientModulus;
	long plainTextModulus;
	long polynomialModulusExponent;
	double noiseStandardDeviation;
	
	
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
     */
	public FVParameters(SecurityParam bos, long n, long q, long t, double sigma)
	{
		coefficientModulus = q;
		polynomialModulusExponent = n;
		plainTextModulus = t;
		noiseStandardDeviation = sigma;
		CheckParameterConsistency(bos);
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
		return new FVParameters(bos, n, q, t,defaultNoiseSD);
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
	
	public static boolean Is2NCongruent(long v, long n, int c) throws ArithmeticException
	{
		return BigInteger.valueOf(v - c).mod(BigInteger.valueOf(2*n)).intValue() == 0;
	}
	
	
}
