/**
 * 
 */
package com.n1analytics.fvvector;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/**
 * @author har991
 *
 */
public class FVPlainText {
	
	UnivariatePolynomialZp64 encoding;
	
	public FVPlainText()
	{
	}
	
	public void encode(FVContext pgen, long[] data)
	{
		FVEncoder encoder = new FVEncoder(pgen);
		encoding = encoder.encode(data);
	}
	
	public long[] decode(FVContext pgen)
	{
		FVEncoder encoder = new FVEncoder(pgen);
		return encoder.decode(encoding);
	}
	
	public void set(UnivariatePolynomialZp64 in)
	{
		encoding = in.copy();
	}
	
	public FVCipherText encrypt(FVContext pg, FVPublicKey pubKey)
	{
		UnivariatePolynomialZp64 u = pg.generateSmallCTPolynomial();
		UnivariatePolynomialZp64 e1 = pg.generateNoiseCTPolynomial();
		UnivariatePolynomialZp64 e2 = pg.generateNoiseCTPolynomial();
		
		long delta = pg.params.coefficientModulus / pg.params.plainTextModulus;
		// ct = ([∆m + p0u + e1]q, [p1u + e2]q)
		UnivariatePolynomialZp64 field0 = 
				pg.ctPolyField.add(
							pg.ctPolyField.multiply(encoding.setModulus(u.ring), delta),
							pg.ctPolyField.multiply(pubKey.polys.get(0), u),
							e1
						);
		
		UnivariatePolynomialZp64 field1 = 
				pg.ctPolyField.add(
							pg.ctPolyField.multiply(pubKey.polys.get(1), u),
							e2
						);
		FVCipherText ret = new FVCipherText();
		ret.set(field0,  field1);
		return ret;
	}
}
