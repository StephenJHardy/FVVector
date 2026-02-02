/**
 * 
 */
package com.humanata.fvvector;


import cc.redberry.rings.poly.univar.*;


/**
 * @author har991
 *
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
