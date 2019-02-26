package com.n1analytics.fvvector;

import static cc.redberry.rings.Rings.Z;
import static cc.redberry.rings.Rings.Zp64;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;

import cc.redberry.rings.IntegersZp64;
import cc.redberry.rings.bigint.BigInteger;
import cc.redberry.rings.poly.FiniteField;
import cc.redberry.rings.poly.univar.UnivariatePolynomial;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/**
 * @author har991
 *
 *	Class to hide the complexities of using the redberry rings
 *  module for polynomial manipulations.
 *  
 *  This class will not check that the parameters of the FV system
 *  are correct - it is assumed that the inputs are correct with
 *  respect to those parameters.
 *  
 */
public class PolynomialUtils {
	
	/**
	 * To make rotations of slots work, the roots of unity need to be in
	 * a particular order, and the substitutions that must happen for the
	 * a given rotation have to correspond to that order.
	 * 
	 * This function returns an ordering of the powers of the generator of 
	 * the group that gives the right pattern of rotations.
	 * 
	 * There is probably some very nice sophisticated (or simple!) bit of 
	 * maths to make this happen, but I don't know it (yet).
	 * 
	 * @param n number of elements in the encoding
	 * @return an array of the power the generator must be raised to
	 */
	public static long[] CalculateMappingOfRoots(long n)
	{
		long res[] = new long[(int)n];
		int halfn = (int)n/2;
		long twon = 2*n;
		res[0] = 1;
		res[halfn] = 2*n - 1;
		long factor = 2*n - 3;
		for(int i = 1; i < halfn; i++)
		{
			res[i] = Math.floorMod(res[i-1]*factor, twon);
			res[halfn + i] = Math.floorMod(res[halfn+i-1]*factor, twon);			
		}
		return res;
	}
	
	
	/**
	 * Calculates a k such that  k^2n mod t == 1 and where k^i mod t != 1 
	 * for all i != 2n
	 * Then the other roots of unity are k^(2i+1) mod t, i from 0 to n-1
	 * 
	 * Cool fact: Prod(i=0)(i=n-1) (x-k^(2i+1)) = x^n + 1 mod t
	 * 
	 * @param n  subgroup size
	 * @param t  prime and congruent to 1 mod 2n
	 * @return
	 */
	public static long[] CalculateRootsOfUnity(long n, long t)
	{
		long twon = n * 2L;
		long gen = 0L;
		IntegersZp64 cfRing = Zp64(t);
		for(long k = 1L; k < t; k++)
		{
			long res = cfRing.powMod(k,twon);
			if(res == 1)
			{
				boolean soleRoot = true;
				for(long j = 1L; j < twon; j++)
				{
					if(cfRing.powMod(k, j) == 1L)
					{
						soleRoot = false;
						break;
					}
				}
				if(soleRoot)
				{
					gen = k;
					break;
				}
			}
		}
		
		long [] rootMapping = PolynomialUtils.CalculateMappingOfRoots(n);
		long [] rootsOfUnity = new long[(int)n];
		rootsOfUnity[0] = gen;
		for(int k = 1; k < (int)n; k++)
			rootsOfUnity[k] = cfRing.powMod(gen, rootMapping[k]);
		return rootsOfUnity;
	}

	/**
	 * 
	 * Calculate the polynomials that allow projections into and out of the slots
	 * in the plaintext. They are a set of polynomials, b_j(x) such that if we call 
	 * the roots of unity a_i, then b_j(a_i) = \delta_{ij} - that is, if you evaluate
	 * the polynomials at the roots of unity, they are 1 for only their corresponding
	 * polynomial and zero otherwise.
	 * To encode a message v_i we write m(x) = Sum_i v_i b_i(x)
	 * And the components of the message can be obtained from v_i = m(a_i)
	 * 
	 * @param n number of slots
	 * @param t prime and congruent to 1 mod 2n
	 * @param rootsOfUnity precalculated roots of unity for n and t
	 * @return
	 */
	public static UnivariatePolynomialZp64[] CalculateBasisFunctions(long n, long t, long[] rootsOfUnity)
	{
		
		IntegersZp64 cfRing = Zp64(t);
		UnivariatePolynomialZp64[] components = new UnivariatePolynomialZp64[(int)n];
		// calculate (x-a_i) polynomials
		for(int i = 0; i < n; i++)
		{
			long[] npoly3 = new long[(int)n+1];
			npoly3[0]= -rootsOfUnity[i];
			npoly3[1] = 1L;
			components[i] = UnivariatePolynomialZp64.create(t,npoly3);
		}

		UnivariatePolynomialZp64[] bases = new UnivariatePolynomialZp64[(int)n];
		for(int i = 0; i < n; i++)
		{
			// calculate the product of all the (x-a_k) except the ith
			// this is the basis polynomial, except for a normalising factor
			bases[i] = UnivariatePolynomialZp64.one(cfRing);
			for(int k = 0; k < n; k++)
			{
				if(k==i) { continue;}
				bases[i] = bases[i].multiply(components[k]);
			}
			// evaluate this product at the ith root
			long value = bases[i].evaluate(rootsOfUnity[i]);
			// calculate the normalising factor
			long inv = cfRing.reciprocal(value);
			bases[i] = bases[i].multiply(inv);
		}
		return bases;
	}

	
	static SecureRandom getSecureRandom()
	{
		SecureRandom sec = null;
//		try
//		{
//			sec = SecureRandom.getInstanceStrong();
//		} catch(NoSuchAlgorithmException nse)
//		{
			sec = new SecureRandom();
//		}
		return sec;
	}
	
	// Static implementation methods for general parameters
	
	/**
	 * Calculate a polynomial with coefficients from (-1,0,1) with order n - 1 
	 * and modulus t
	 * 
	 * @param n number of coefficients (i.e. order is n-1)
	 * @param t modulus for polynomial ring
	 * @return
	 */
	public static UnivariatePolynomialZp64 generateSmallPolynomial(long n, long t)
	{
		SecureRandom sec = getSecureRandom();
		
		long[] randomElements = new long[(int)n];
		for(int i = 0; i < n; i++)
		{
			randomElements[i] = (long)sec.nextInt(3) - 1L; // -1,0,1 randomly distributed
		}
		return UnivariatePolynomialZp64.create(t, randomElements);
	}
	
	/**
	 * Generate a polynomial with n coefficients (i.e. order x^(n-1)) modulo t
	 * where there is an equal probability of ech value from 0 to t-1.
	 * 
	 * @param n   number of coefficients
	 * @param t   modulus of coefficients
	 * @return
	 */
	public static UnivariatePolynomialZp64 generateUniformPolynomial(long n, long t)
	{
		SecureRandom sec = getSecureRandom();

		long[] randomElements = new long[(int)n];
		for(int i = 0; i < n; i++)
		{
		   long bits, val; // FROM https://stackoverflow.com/questions/2546078/java-random-long-number-in-0-x-n-range
		   do {
		      bits = (sec.nextLong() << 1) >>> 1;
		      val = bits % n;
		   } while (bits-val+(n-1) < 0L);
		   randomElements[i] = val;
		}
		return UnivariatePolynomialZp64.create(t, randomElements);
	}

	/**
	 * Generate a polynomial with n coefficients (i.e. order n-1) which are numbers
	 * modulo t. The distribution of these coefficients is a truncated gaussian
	 * with variance sigma and cutoff sigmamax.
	 * 
	 * @param n number of coefficients
	 * @param t modulus of coefficients
	 * @param sigma  variance of distribution
	 * @param sigmamax cutoff of distribution
	 * @return polynomial with noise ceofficients
	 */
	public static UnivariatePolynomialZp64 generateNoisePolynomial(long n, long t, double sigma, double sigmamax)
	{
		if(sigma <= 0) throw new IllegalArgumentException("Negative noise sigma used");
		if(sigmamax <= 0) throw new IllegalArgumentException("Negative noise sigmamax used");

		SecureRandom sec = getSecureRandom();

		long[] randomElements = new long[(int)n];
		double range = sigmamax / sigma;
		for(int i = 0; i < n; i++)
		{		
			double gv = 2*range;
			while(Math.abs(gv) > range)
				gv = sec.nextGaussian();
			randomElements[i] = Math.round(gv * sigma); // round to nearest long
		}
		return UnivariatePolynomialZp64.create(t, randomElements);		
	}

	/**
	 * Divide each coefficient in the polynomial by the divisor. Done as integers, not
	 * in a finite field, and done in place.
	 * 
	 * @param poly  poly to divide
	 * @param divisor integer to divide by
	 */
	public static void polynomialCoefficientDivisionInPlace(UnivariatePolynomialZp64 poly, long divisor)
	{
		for(int j = 0; j < poly.size(); j++)
			poly.set(j,poly.get(j)/divisor);
	}
	
	public static ArrayList<UnivariatePolynomialZp64> decomposePolynomial(UnivariatePolynomialZp64 polyIn, long base)
	{
		UnivariatePolynomialZp64 poly = polyIn.copy();
		long q = poly.modulus();
		long l = (long)Math.floor(Math.log(q)/Math.log(base)) + 1;
		ArrayList< UnivariatePolynomialZp64 > res = new ArrayList< UnivariatePolynomialZp64 >((int)l);
		
		for(int i = 0 ; i < (int)l; i++)
		{
			UnivariatePolynomialZp64 pcur = poly.setModulus(base);
			UnivariatePolynomialZp64 tosub = pcur.copy().setModulus(q);
			res.add(tosub.copy());
			poly = poly.subtract(tosub);
			polynomialCoefficientDivisionInPlace(poly,base);
		}
		return res;
	}
		
	
	/**
	 * Take the dot product of two arrays of polynomials and accumulate
	 * the results into a given polynomial. The dot products are accumulation
	 * are done in the finite field speificied.
	 * 
	 * @throws RuntimeException if arrays are not the same size
	 * @param field finite field in which to do the operations
	 * @param accumulator polynomial to add the dot product result to
	 * @param parray1 first array of polynomials
	 * @param parray2 second array of polynomials
	 * @return
	 */
	public static UnivariatePolynomialZp64 accumulateDotProduct(
		FiniteField<UnivariatePolynomialZp64> field,
		UnivariatePolynomialZp64 accumulator,
		ArrayList<UnivariatePolynomialZp64> parray1, 
		ArrayList<UnivariatePolynomialZp64> parray2
		)
	{
		if(parray1.size() != parray2.size())
			throw new RuntimeException("array sizes must be matching in accumulateDotProduct");

		UnivariatePolynomialZp64 newp = accumulator.clone();
		UnivariatePolynomialZp64 tmp1, tmp2, tmp3;
		for(int i = 0; i < parray1.size(); i++)
		{
			tmp1 = parray1.get(i);
			tmp2 = parray2.get(i);
			tmp3 = field.multiply(
					tmp1,
					tmp2
			);
			newp = newp.add(tmp3);
		}
		return newp;
	}
	
	/**
	 * Return a polynomial with the accumulated dot product of an array
	 * of polynomials with powers of a given polynomials. All operations
	 * should be done in the finite field given. This is a key step
	 * in the FV decryption process.
	 * 
	 * [Sum parray_i atom^i] mod q mod x^n + 1
	 * 
	 * @param field field under which the operations are to be performed
	 * @param parray array of polynomials 
	 * @param atom polynomial which will have powers calculated
	 * @return polynomial with sum
	 */
	public static UnivariatePolynomialZp64 dotProducWithPowers(
			FiniteField<UnivariatePolynomialZp64> field,
			ArrayList<UnivariatePolynomialZp64> parray, 
			UnivariatePolynomialZp64 atom)
	{		
		if(parray.size() == 0)
		{
			return atom.createZero();
		}

		// c0 + c1 s + ... + c_k s^k
		UnivariatePolynomialZp64 sum = parray.get(0).clone(); // take a copy
		UnivariatePolynomialZp64 power = atom.clone(); // take a copy
		for(int i = 1; i < parray.size(); i++)
		{
			sum = field.add(
						sum,
						field.multiply(parray.get(i), power)
					);
			power = field.multiply(power, atom);
		}
		return sum;
	}
	
	/**
	 * Divide the coefficients of the given polynomial by the given factor
	 * and round the results, then reduce to the target field.
	 * 
	 * @param field  field in which the returned polynomial will lie
	 * @param poly polynomial to divide
	 * @param factor integer to divide by
	 * @return rescaled polynomial in given field
	 */
	public static UnivariatePolynomialZp64 dividePolynomialAndRoundInField(
			FiniteField<UnivariatePolynomialZp64> field,
			UnivariatePolynomialZp64 poly,
			long factor
			)
	{
	
		int sz = (int)field.getMinimalPolynomial().size() - 1; // x^n + 1 has n + 1 coeffs.
		long[] res = new long[sz];
	
		for(int i = 0; i < sz; i++)
		{
			double tmp = (double)poly.get(i) / (double)factor; // this should be integer arithmetic!
			res[i] = Math.round(tmp);
		}
				
		return field.factory().createFromArray(res);
	}
	
	/**
	 * Implements the basic algorithm for FV ciphertext multiplication. This must
	 * be done in a very particular way to give correct results.
	 * The two polynomial arrays are multiplied as if they are polynomials in the
	 * secret key, this results in another array of polynomials with more
	 * elements. The coefficients of tehse are then divided by a scale, then the 
	 * resulting polynomials are reduced modulo the quotient polynomial and 
	 * ring modulus.
	 * 
	 * @param field The field of the final polynomial
	 * @param polys1 first array of polynomials
	 * @param polys2 second array of polynomials
	 * @param scale amount to divide product by
	 * @return array of polynomails
	 */
	public static ArrayList<UnivariatePolynomialZp64> multiplyPolyArraysDivideAndRound(
			FiniteField<UnivariatePolynomialZp64> field,
			ArrayList< UnivariatePolynomialZp64> polys1,
			ArrayList< UnivariatePolynomialZp64> polys2,
			long scale
			)
	{
		int sz = (polys1.size() - 1) + (polys2.size() - 1) + 1;
		
		// The multiplication must be done in a particular way.
		// The product of the polynomials needs to be calculated then divided by the ciphertext modulus
		// before the reduction modulo the polynomial
		
		// overflow is likely for moduli, so we use big integers
		ArrayList< UnivariatePolynomial<BigInteger> > bres = new ArrayList< UnivariatePolynomial<BigInteger> >(sz);
				
		for(int i = 0; i < sz; i++)
		{
			bres.add(UnivariatePolynomial.zero(Z));
		}
		
		for(int i = 0; i < polys1.size(); i++)
		{
			UnivariatePolynomial<BigInteger> pb1 = polys1.get(i).asPolyZ(true).toBigPoly();
			
			for(int j = 0; j < polys2.size(); j++)
			{				
				UnivariatePolynomial<BigInteger> pb2 = polys2.get(j).asPolyZ(true).toBigPoly();
				UnivariatePolynomial<BigInteger> bprod = pb1.clone().multiply(pb2);		
				UnivariatePolynomial<BigInteger> baccum = bres.get(i+j).add(bprod);
				bres.set(i+j, baccum);
			}
		}
		
		for(int i = 0; i < bres.size(); i++)
		{			
			UnivariatePolynomial<BigInteger> bp = bres.get(i);
			for(int j = 0; j < bp.size(); j++)
			{
				BigInteger resandrem[] = bp.get(j).divideAndRemainder(BigInteger.valueOf(scale));
				long rem = resandrem[1].longValue();
				if(rem*2 > scale)
					resandrem[0] = resandrem[0].add(BigInteger.valueOf(1));
				bp.set(j, resandrem[0]);
			}
		}
		
		ArrayList< UnivariatePolynomialZp64 > retval = new ArrayList< UnivariatePolynomialZp64 >(sz);
		for(int i = 0; i < bres.size(); i++)
		{
			UnivariatePolynomial<BigInteger> bp = bres.get(i);
			retval.add(i,
					field.valueOf(
							UnivariatePolynomial.asOverZp64(bp,
									field.getMinimalPolynomial().ring)));
		}

		return retval;
	}
	
	public static UnivariatePolynomialZp64 coeffTransform(UnivariatePolynomialZp64 poly, long power, long order)
	{
		long val[] = new long[(int)order];
		for(int i = 0; i < order; i++)
		{
			long newLoc = Math.floorMod(i*power, order);
			long sign = 1;
			if((Math.floorDiv(i*power, order)&1) == 1)
				sign = -1;
			val[(int)newLoc] = poly.get(i)*sign;
		}
		return poly.createFromArray(val);
	}
	
}
