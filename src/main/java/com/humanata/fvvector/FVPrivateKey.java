/**
 * 
 */
package com.humanata.fvvector;


import cc.redberry.rings.poly.univar.*;


/**
 * Represents the private key for the FV cryptosystem.
 * <p>
 * <b>For experimentation and learning only.</b> Not for production use.
 * This class does not support serialization.
 *
 * @author har991
 */
public class FVPrivateKey {
	
	private final UnivariatePolynomialZp64 privateKeyPolynomial;
	FVParameters params;
	
	FVPrivateKey(FVParameters params)
	{
		this.params = params;
		this.privateKeyPolynomial = params.generateSmallCTPolynomial();
	}		
		
	UnivariatePolynomialZp64 key()
	{
		return privateKeyPolynomial;
	}
		

}
