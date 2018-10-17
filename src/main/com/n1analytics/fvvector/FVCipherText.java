package com.n1analytics.fvvector;

import java.util.ArrayList;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

public class FVCipherText {

	ArrayList< UnivariatePolynomialZp64 > polys = new ArrayList< UnivariatePolynomialZp64 >();
	
	FVCipherText()
	{
	}
	
	protected FVCipherText clone() {
		FVCipherText ret = new FVCipherText();
		for(int i = 0; i < polys.size(); i++)
			ret.polys.add(polys.get(i).clone());
		return ret;
	}
	
	FVPlainText decrypt(FVContext pg, FVPrivateKey privKey)
	{
		 // c0 + c1 s + ... + c_k s^k
		UnivariatePolynomialZp64 sum = polys.get(0).clone(); // take a copy
		UnivariatePolynomialZp64 keypower = privKey.key().clone(); // take a copy
		for(int i = 1; i < polys.size(); i++)
		{
			sum = pg.ctPolyField.add(
						sum,
						pg.ctPolyField.multiply(polys.get(i), keypower)
					);
			keypower = pg.ctPolyField.multiply(keypower, privKey.key());
		}
		long[] ref = sum.getDataReferenceUnsafe();
		double delta = (double)pg.params.coefficientModulus / (double)pg.params.plainTextModulus;
		long[] res = new long[ref.length];

		for(int i = 0; i < res.length; i++)
		{
			double tmp = (double)ref[i] / delta;
			res[i] = Math.round(tmp);
		}
		
		FVPlainText ret = new FVPlainText();
		ret.set(UnivariatePolynomialZp64.create(pg.params.plainTextModulus, res));
		
		return ret;
	}
	
	void set(UnivariatePolynomialZp64 field0, UnivariatePolynomialZp64 field1)
	{
		polys.clear();
		polys.add(field0.copy());
		polys.add(field1.copy());
	}
	
	void addTo(FVContext pg, FVCipherText ct2)
	{
		while(polys.size() < ct2.polys.size())
		{
			polys.add(pg.ctPolyField.getZero());
		}
		for(int i = 0; i < ct2.polys.size(); i++)
		{
			polys.get(i).add(ct2.polys.get(i));
		}
	}
	
	FVCipherText add(FVContext pg, FVCipherText ct2)
	{
		FVCipherText ret = this.clone();
		ret.addTo(pg, ct2);
		return ret;
	}

	void multiplyBy(FVContext pg, FVCipherText ct2)
	{
	}

}
