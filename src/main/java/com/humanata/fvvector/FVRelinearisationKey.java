package com.humanata.fvvector;

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

public class FVRelinearisationKey {
	
	// Each relinearisation key is represented by a set of two polynomials
	// These polynomials represented masked noisy versions of the square of the 
	// secret key.
	
	ArrayList< UnivariatePolynomialZp64 > polys0 = new ArrayList< UnivariatePolynomialZp64 >();
	ArrayList< UnivariatePolynomialZp64 > polys1 = new ArrayList< UnivariatePolynomialZp64 >();

	FVParameters params;

	/**
	 * 
	 * Construct a relinearisation key from a private key.
	 * 
	 * @param privKey the private key to generate the public key from
	 * 
	 */
	public FVRelinearisationKey(FVPrivateKey privKey)
	{
		this.params = privKey.params;
		UnivariatePolynomialZp64 s2 = privKey.params.ctPolyField.multiply(privKey.key(), privKey.key());
		
		for(long i=0; i <= params.l; i++)
		{
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
						privKey.params.ctPolyField.multiply(s2, (long)Math.pow(params.decompositionBase, i))
					);

			polys0.add(r);
			polys1.add(a);	
		}
	}
	
	
}
