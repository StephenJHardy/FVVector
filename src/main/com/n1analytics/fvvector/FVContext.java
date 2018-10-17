package com.n1analytics.fvvector;

import static cc.redberry.rings.Rings.GF;

import java.security.SecureRandom;

import static cc.redberry.rings.Rings.*;

import cc.redberry.rings.IntegersZp64;
import cc.redberry.rings.poly.FiniteField;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

public class FVContext {

	public FVParameters params;

	IntegersZp64 ptRing;
	IntegersZp64 ctRing;
	UnivariatePolynomialZp64 ptQuotientPoly;
	UnivariatePolynomialZp64 ctQuotientPoly;
	FiniteField<UnivariatePolynomialZp64> ptPolyField;
	FiniteField<UnivariatePolynomialZp64> ctPolyField;

	long rootsOfUnity[];
	UnivariatePolynomialZp64 bases[];
	
	private static final SecureRandom sec = new SecureRandom();
	
	FVContext(FVParameters params)
	{
		this.params = params;
		ConstructPolynomialField();
		this.rootsOfUnity = CalculateRootsOfUnity(params.polynomialModulusExponent, params.plainTextModulus);
		this.bases = CalculateBasisFunctions(params.polynomialModulusExponent, params.plainTextModulus, rootsOfUnity);
	}

	/**
	 *  Construct the object that represents polynomials in the plaintext and ciphertext spaces
	 */
	private void ConstructPolynomialField() {
		long[] data = new long[(int)params.polynomialModulusExponent + 1];
		data[0] = 1L;
		data[(int)params.polynomialModulusExponent]=1L;

		this.ptQuotientPoly = UnivariatePolynomialZp64.create(params.plainTextModulus, data);
		this.ptPolyField = GF(ptQuotientPoly);
		this.ptRing = ptQuotientPoly.ring;
		this.ctQuotientPoly = UnivariatePolynomialZp64.create(params.coefficientModulus, data);
		this.ctPolyField = GF(ctQuotientPoly);		
		this.ctRing = ctQuotientPoly.ring;
		
	}

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

	public UnivariatePolynomialZp64 generateSmallPTPolynomial()
	{
		return generateSmallPolynomial(params.polynomialModulusExponent, params.plainTextModulus);
	}
	
	public UnivariatePolynomialZp64 generateSmallCTPolynomial()
	{
		return generateSmallPolynomial(params.polynomialModulusExponent, params.coefficientModulus);
	}
	
	public UnivariatePolynomialZp64  generaateUniformCTPolynomial()
	{
		return generateUniformPolynomial(params.polynomialModulusExponent, params.coefficientModulus);
	}
	
	public UnivariatePolynomialZp64 generateNoiseCTPolynomial()
	{
		// 9.4 magic number in the following comes from the initial FV paper as a bound where < 2-64 chance of hitting an integer outside this range.
		return generateNoisePolynomial(params.polynomialModulusExponent, params.coefficientModulus, params.noiseStandardDeviation, 9.4*params.noiseStandardDeviation);
	}

	
	// Static implementation methods for general parameters
	
	public static UnivariatePolynomialZp64 generateSmallPolynomial(long n, long t)
	{
		long[] randomElements = new long[(int)n];
		for(int i = 0; i < n; i++)
		{
			randomElements[i] = (long)sec.nextInt(3) - 1L; // -1,0,1 randomly distributed
		}
		return UnivariatePolynomialZp64.create(t, randomElements);
	}
	
	public static UnivariatePolynomialZp64 generateUniformPolynomial(long n, long t)
	{
		long[] randomElements = new long[(int)n];
		for(int i = 0; i < n; i++)
		{
			randomElements[i] = (long)sec.nextInt((int)t); 
		}
		return UnivariatePolynomialZp64.create(t, randomElements);
	}

	public static UnivariatePolynomialZp64 generateNoisePolynomial(long n, long t, double sigma, double sigmamax)
	{
		if(sigma <= 0) throw new IllegalArgumentException("Negative noise sigma used");
		if(sigmamax <= 0) throw new IllegalArgumentException("Negative noise sigmamax used");
		
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
