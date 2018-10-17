/**
 * 
 */
package com.n1analytics.fvvector;


import java.util.ArrayList;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/**
 * @author har991
 *
 */
public class FVPublicKey {
	ArrayList< UnivariatePolynomialZp64 > polys = new ArrayList< UnivariatePolynomialZp64 >();
	
//	Calculate ([−(as + e)]q , a)
	
	public FVPublicKey(FVContext pg, FVPrivateKey privKey)
	{
		UnivariatePolynomialZp64 a = pg.generaateUniformCTPolynomial();
		UnivariatePolynomialZp64 e = pg.generateNoiseCTPolynomial();
		
		UnivariatePolynomialZp64 r = 				
			pg.ctPolyField.negate(
				pg.ctPolyField.add( 
						pg.ctPolyField.multiply(a, privKey.key())
						,  e
						)
				);

		polys.add(r);
		polys.add(a);	
	}
	


}
