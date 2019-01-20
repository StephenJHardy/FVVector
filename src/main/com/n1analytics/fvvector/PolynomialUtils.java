package com.n1analytics.fvvector;

import static cc.redberry.rings.Rings.Zp64;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import cc.redberry.rings.IntegersZp64;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

public class PolynomialUtils {
	
	public static long[] CalculateRootsOfUnity(long n, long t)
	{
		// find ks such that k^2n mod t == 1
		// and where k^i mod t != 1 for all i != 2n
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
		long [] rootsOfUnity = new long[(int)n];
		rootsOfUnity[0] = gen;
		for(long k = 1; k < n; k++)
			rootsOfUnity[(int)k] = cfRing.powMod(gen, 2L*k + 1L);
		return rootsOfUnity;
	}

	public static UnivariatePolynomialZp64[] CalculateBasisFunctions(long n, long t, long[] rootsOfUnity)
	{
		
		IntegersZp64 cfRing = Zp64(t);
		UnivariatePolynomialZp64[] components = new UnivariatePolynomialZp64[(int)n];
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
			bases[i] = UnivariatePolynomialZp64.one(cfRing);
			for(int k = 0; k < n; k++)
			{
				if(k==i) { continue;}
				bases[i] = bases[i].multiply(components[k]);
			}
			long value = bases[i].evaluate(rootsOfUnity[i]);
			long inv = cfRing.reciprocal(value);
			bases[i] = bases[i].multiply(inv);
		}
		return bases;
	}

	
	// Static implementation methods for general parameters
	
	public static UnivariatePolynomialZp64 generateSmallPolynomial(long n, long t)
	{
		SecureRandom sec = null;
		try
		{
			sec = SecureRandom.getInstanceStrong();
		} catch(NoSuchAlgorithmException nse)
		{
			sec = new SecureRandom();
		}
		
		long[] randomElements = new long[(int)n];
		for(int i = 0; i < n; i++)
		{
			randomElements[i] = (long)sec.nextInt(3) - 1L; // -1,0,1 randomly distributed
		}
		return UnivariatePolynomialZp64.create(t, randomElements);
	}
	
	public static UnivariatePolynomialZp64 generateUniformPolynomial(long n, long t)
	{
		SecureRandom sec = null;
		try
		{
			sec = SecureRandom.getInstanceStrong();
		} catch(NoSuchAlgorithmException nse)
		{
			sec = new SecureRandom();
		}
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

	public static UnivariatePolynomialZp64 generateNoisePolynomial(long n, long t, double sigma, double sigmamax)
	{
		if(sigma <= 0) throw new IllegalArgumentException("Negative noise sigma used");
		if(sigmamax <= 0) throw new IllegalArgumentException("Negative noise sigmamax used");

		SecureRandom sec = null;
		try
		{
			sec = SecureRandom.getInstanceStrong();
		} catch(NoSuchAlgorithmException nse)
		{
			sec = new SecureRandom();
		}

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

	
}
