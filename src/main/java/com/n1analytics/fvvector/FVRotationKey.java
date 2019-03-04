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

	ArrayList< ArrayList< UnivariatePolynomialZp64 > > keys0;
	ArrayList< ArrayList< UnivariatePolynomialZp64 > > keys1;

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

		keys0 = new ArrayList< ArrayList< UnivariatePolynomialZp64 > >((int)params.polynomialModulusExponent);
		keys1 = new ArrayList< ArrayList< UnivariatePolynomialZp64 > >((int)params.polynomialModulusExponent);		
				
		for(int k = 0; k <= params.polynomialModulusExponent/2; k++)
		{
			keys0.add(new ArrayList< UnivariatePolynomialZp64 > ((int)params.l + 1));
			keys1.add(new ArrayList< UnivariatePolynomialZp64 > ((int)params.l + 1));
			
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
		
}
