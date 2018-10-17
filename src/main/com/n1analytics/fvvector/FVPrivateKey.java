/**
 * 
 */
package com.n1analytics.fvvector;


import cc.redberry.rings.poly.univar.*;


/**
 * @author har991
 *
 */
public class FVPrivateKey {
	
	private final UnivariatePolynomialZp64 privateKeyPolynomial;
	private FVParameters params;
	
	FVPrivateKey(FVContext pgen)
	{
		params = pgen.params;
		privateKeyPolynomial = pgen.generateSmallCTPolynomial();
	}		
		
	UnivariatePolynomialZp64 key()
	{
		return privateKeyPolynomial;
	}
		

}
