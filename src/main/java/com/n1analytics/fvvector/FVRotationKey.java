package com.n1analytics.fvvector;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/**
 *
 * This class represents a set of keys for the FV cryptosystem that allows a ciphertext
 * with three elements to be reduced to a ciphertext with only two elements, at the expense
 * of some additional noise in the cyphertext
 * 
 * @author har991
 *
 */

public class FVRotationKey {
	

	FVParameters params;
	FVEncoder encoder;

	private ArrayList< ArrayList< UnivariatePolynomialZp64 > > keys0;
	private ArrayList< ArrayList< UnivariatePolynomialZp64 > > keys1;

	/**
	 * 
	 * Construct a set of rotation keys from a private key and an encoder.
	 * 
	 * @param privKey the private key to generate the public key from
	 * 
	 */
	public FVRotationKey(FVPrivateKey privKey, FVEncoder encoder)
	{
		if(privKey.params != encoder.params)
			throw new RuntimeException("parameters must match in inputs to FVRotationKey constructor");
		
		this.params = privKey.params;
		this.encoder = encoder;

		keys0 = new ArrayList< ArrayList< UnivariatePolynomialZp64 > >(numberOfKeys());
		keys1 = new ArrayList< ArrayList< UnivariatePolynomialZp64 > >(numberOfKeys());
				
		for(int k = 0; k <= params.polynomialModulusExponent/2; k++)
		{
			keys0.add(new ArrayList< UnivariatePolynomialZp64 > (elementsPerKey()));
			keys1.add(new ArrayList< UnivariatePolynomialZp64 > (elementsPerKey()));
			
			for(long i=0; i <= params.l; i++)
			{
				UnivariatePolynomialZp64 srot = PolynomialUtils.coeffTransform(privKey.key().clone(), encoder.generatorPowers[k], params.polynomialModulusExponent);
				UnivariatePolynomialZp64 smod = 
						privKey.params.ctPolyField.add(
								privKey.params.ctPolyField.negate(privKey.key()),
								srot);
				
				UnivariatePolynomialZp64 a = privKey.params.generaateUniformCTPolynomial();
				UnivariatePolynomialZp64 e = privKey.params.generateNoiseCTPolynomial();
			
				UnivariatePolynomialZp64 r =
						privKey.params.ctPolyField.add(
							privKey.params.ctPolyField.negate(
								privKey.params.ctPolyField.add( 
									privKey.params.ctPolyField.multiply(a, privKey.key())
									,  e
								)
							),
							privKey.params.ctPolyField.multiply(smod, (long)Math.pow(params.decompositionBase, i))
						);
	
				keys0.get(k).add(r.copy());
				keys1.get(k).add(a.copy());	
			}
		}	
	}

	public int numberOfKeys()
	{
		return (int)params.polynomialModulusExponent/2 + 1;
	}

	public int elementsPerKey()
	{
		return (int)params.l + 1;
	}


	/**
	 *
	 * Return the set of polynomials used to rekey the first element of a ciphertext that has been transformed by
	 * the given index.
	 *
	 * @param index the index of the transformation used (as implemented in the encoder class
	 * @return an array list of polynomials with the correction factors
	 *
	 */
	public ArrayList< UnivariatePolynomialZp64 > getFirstRekeyingPolynomials(int index)
	{
		return keys0.get(index);
	}

	/**
	 *
	 * Return the set of polynomials used to rekey the second element of a ciphertext that has been transformed by
	 * the given index.
	 *
	 * @param index the index of the transformation used (as implemented in the encoder class
	 * @return an array list of polynomials with the correction factors
	 *
	 */	public ArrayList< UnivariatePolynomialZp64 > getSecondRekeyingPolynomials(int index)
	{
		return keys1.get(index);
	}

}
