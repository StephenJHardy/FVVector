/**
 * 
 */
package com.humanata.fvvector;


import java.util.ArrayList;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/**
 *
 * This class represents a public key for the FV cryptosystem. It is represented by a 
 * pair of polynomials (implemented as an ArrayList) that contains ([−(as + e)]q , a)
 * where s is the secret key polynomial, a is a polynomial with random coefficients
 * and e is a noise polynomial, all polynomials modulo the coefficientModulus.
 * 
 * @author har991
 *
 */
public class FVPublicKey {
	ArrayList< UnivariatePolynomialZp64 > polys = new ArrayList< UnivariatePolynomialZp64 >();

	FVParameters params;
	/**
	 * 
	 * Construct a public key from a private key.
	 * 
	 * @param privKey the private key to generate the public key from
	 * 
	 */
	public FVPublicKey(FVPrivateKey privKey)
	{
		this.params = privKey.params;
		
		UnivariatePolynomialZp64 a = privKey.params.generaateUniformCTPolynomial();
		UnivariatePolynomialZp64 e = privKey.params.generateNoiseCTPolynomial();
		
		UnivariatePolynomialZp64 r = 				
			privKey.params.ctPolyField.negate(
				privKey.params.ctPolyField.add( 
					privKey.params.ctPolyField.multiply(a, privKey.key())
					,  e
				)
			);

		polys.add(r);
		polys.add(a);	
	}
	
	
	/**
	 * Get the first element of the key
	 * @return a polynomial representing the first element of the key
	 */
	UnivariatePolynomialZp64 e0()
	{
		return polys.get(0);
	}

	/**
	 * Get the second element of the key
	 * @return a polynomial representing the second element of the key
	 */
	UnivariatePolynomialZp64 e1()
	{
		return polys.get(1);
	}

}
