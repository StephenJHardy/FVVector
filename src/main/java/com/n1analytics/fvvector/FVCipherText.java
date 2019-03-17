package com.n1analytics.fvvector;

import java.util.ArrayList;

import com.n1analytics.fvvector.FVPlainText;
import com.n1analytics.fvvector.FVPrivateKey;

import cc.redberry.rings.bigint.BigInteger;
//import cc.redberry.rings.poly.univar.UnivariatePolynomial;
//import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

import cc.redberry.rings.*;
import cc.redberry.rings.poly.*;
import cc.redberry.rings.poly.univar.*;
import cc.redberry.rings.poly.multivar.*;

import static cc.redberry.rings.poly.PolynomialMethods.*;
import static cc.redberry.rings.Rings.*;

/**
 * This class represents a cipher text represented as an array of polynomials. This object has simple homomorphic 
 * arithmetic operations defined for it. Given a compatible private key, it can decrypt to a plaintext.
 * 
 */
public class FVCipherText {

	FVParameters params;
	
	/**
	 * List of polynomials in the ciphertext. Initially just 2, but multiplications 
	 * increase the size of the ciphertext.
	 */
	ArrayList< UnivariatePolynomialZp64 > polys = new ArrayList< UnivariatePolynomialZp64 >();
	
	
	/**
	 * Create an empty ciphertext
	 * @param params FV parameter set this ciphertext uses
	 */
	FVCipherText(FVParameters params)
	{
		this.params = params;
	}
	
	
	/**
	 * Copy the given ciphertext. Clones the polynomials in the ciphertext to ensure they are not
	 * modified after copy.
	 * 
	 * @param toClone Cipher text to copy
	 */
	public FVCipherText(FVCipherText toClone) {
		params = toClone.params;
		polys.clear();
		for(int i = 0; i < toClone.polys.size(); i++)
			polys.add(toClone.polys.get(i).clone());	
	}
		
	
	/**
	 * Return the size of the ciphertext (number of polynomials)
	 * @return number of polynomials in the ciphertext
	 */
	int size()
	{
		return polys.size();
	}
	/**
	 * Decrypt the ciphertext using the provided private key
	 * 
	 * @param privKey private key for decryption - parameter consistency will be checked.
	 * @return a FVPlainText object with the decrypted result
	 */
	FVPlainText decrypt(FVPrivateKey privKey)
	{
		if(!privKey.params.equals(this.params))
			throw new RuntimeException("Decryption key parameters do not match ciphertext parameters");
		
		UnivariatePolynomialZp64 sum = 
				PolynomialUtils.dotProducWithPowers(privKey.params.ctPolyField, polys, privKey.key());

		long delta = privKey.params.coefficientModulus / privKey.params.plainTextModulus;

		FVPlainText ret = new FVPlainText();
		ret.set(
				PolynomialUtils.dividePolynomialAndRoundInField(privKey.params.ptPolyField, sum, delta)
				);
		
		return ret;
	}
	
	/**
	 * Set the polynomials in the ciphertext to those specified
	 * 
	 * @param field0 first element of the ciphertext as a polynomial
	 * @param field1 second element of the ciphertext as a polynomial
	 */
	void set(UnivariatePolynomialZp64 field0, UnivariatePolynomialZp64 field1)
	{
		if( (field0.ring.modulus != params.coefficientModulus) ||
		    (field1.ring.modulus != params.coefficientModulus) )
		{
			throw new RuntimeException("Ciphertext polynomials have incorrect modulus");
		}
		polys.clear();
		polys.add(field0.clone());
		polys.add(field1.clone());
	}
	
	
	/**
	 * Add the specified ciphertext to this
	 * 
	 * @param ct2 polynomial to add
	 */
	void addTo(FVCipherText ct2)
	{
		if(!ct2.params.equals(this.params)) 
			throw new RuntimeException("Ciphertext parameters in addition do not match");

		while(polys.size() < ct2.polys.size())
		{
			polys.add(params.ctPolyField.getZero());
		}
		UnivariatePolynomialZp64 tmp1;
		UnivariatePolynomialZp64 tmp2;
		for(int i = 0; i < ct2.polys.size(); i++)
		{
			tmp1 = ct2.polys.get(i);
			tmp2 = polys.get(i).add(tmp1);
			polys.set(i, tmp2);
		}
	}
	
	/**
	 * Subtract the specified ciphertext from this
	 * 
	 * @param ct2 polynomial to add
	 */
	void subtractFrom(FVCipherText ct2)
	{
		if(!ct2.params.equals(this.params)) 
			throw new RuntimeException("Ciphertext parameters in subtraction do not match");

		while(polys.size() < ct2.polys.size())
		{
			polys.add(params.ctPolyField.getZero());
		}
		UnivariatePolynomialZp64 tmp1;
		UnivariatePolynomialZp64 tmp2;
		for(int i = 0; i < ct2.polys.size(); i++)
		{
			tmp1 = ct2.polys.get(i);
			tmp2 = polys.get(i).subtract(tmp1);
			polys.set(i, tmp2);
		}
	}
	
	/**
	 * Multiply the this by the specified ciphertext
	 * 
	 * @param ct2 the polynomial to multiply by
	 */
	void multiplyBy(FVCipherText ct2)
	{
		if(!ct2.params.equals(this.params)) 
			throw new RuntimeException("Ciphertext parameters in multiplication do not match");

		// resulting ciphertext will have new size 
		int sz = (polys.size() - 1) + (ct2.polys.size() - 1) + 1;
		long scale = params.coefficientModulus / params.plainTextModulus;
		
		polys =
				PolynomialUtils.multiplyPolyArraysDivideAndRound(
						params.ctPolyField,
						this.polys,
						ct2.polys,
						scale
						);
		return;
	}

	/**
	 * Multiply the this by the specified plaintext
	 * 
	 * @param pt the plaintext to multiply by
	 */
	void multiplyBy(FVPlainText pt)
	{
		// @todo: add parameters block to plaintext to make this check correct.
		if(pt.encoding.size() != this.params.polynomialModulusExponent) 
			throw new RuntimeException("Plaintext size does not match in multiplication");

		polys = PolynomialUtils.multiplyPolyArrayByPoly(params.ctPolyField, polys, pt.encoding.setModulus(params.coefficientModulus));
		return;
	}
	
	
	/**
	 * Relinearise this ciphertext from three elements to two
	 * 
	 * @param rk the key to use for relinearisation
	 */
	void relineariseCubic(FVRelinearisationKey rk)
	{
		if(!rk.params.equals(this.params)) 
			throw new RuntimeException("Ciphertext parameters in relinearisation key do not match");
		if(polys.size() == 2)
			throw new RuntimeException("Relinearising a ciphertext with only 2 elements");
		if(polys.size() > 3)
			throw new RuntimeException("Relinearising a ciphertext with more than 3 elements - currently unsupported");

		ArrayList< UnivariatePolynomialZp64 > decomp = PolynomialUtils.decomposePolynomial(polys.get(2), params.decompositionBase);
		
		UnivariatePolynomialZp64 newc0 =
				PolynomialUtils.accumulateDotProduct(params.ctPolyField, polys.get(0), rk.polys0, decomp);
		UnivariatePolynomialZp64 newc1 =
				PolynomialUtils.accumulateDotProduct(params.ctPolyField, polys.get(1), rk.polys1, decomp);
				
		polys.clear();
		polys.add(newc0);
		polys.add(newc1);
	}
	
	/**
	 * Decrypt the cipher text and determine what the maximum deviation from the lattice points 
	 * in the plain text polynomial space is. A number close to 0.5 means that the ciphertext is
	 * likely not to have decypted properly.
	 *  
	 * @param privKey private key to do the decryption with
	 * @return double measure from 0.0 to 0.5 - smaller means less noise.
	 */
	double measureCTNoise(FVPrivateKey privKey)
	{
		if(!privKey.params.equals(this.params))
			throw new RuntimeException("Decryption key parameters do not match ciphertext parameters");
		
		UnivariatePolynomialZp64 sum = 
				PolynomialUtils.dotProducWithPowers(privKey.params.ctPolyField, polys, privKey.key());

		double delta = (double)privKey.params.coefficientModulus / (double)privKey.params.plainTextModulus;
		long[] res = new long[(int)privKey.params.polynomialModulusExponent];

		double maxDev = 0.0;
		for(int i = 0; i < res.length; i++)
		{
			double tmp = sum.get(i) / delta;
			res[i] = Math.round(tmp);			
			double dev = Math.abs(res[i] - tmp);
			if(dev > maxDev) maxDev = dev;
		}
		
		return maxDev;
	}

	/**
	 * Transform this ciphertext using the given rotation element in the encoder
	 * 
	 * @param encoder the encoder for the data stored in the ciphertext
	 * @param index the element of the basis to usefor the rotation
	 */
	void rotate(FVEncoder encoder, int index)
	{
		if(polys.size() != 2)
			throw new RuntimeException("Rotating a ciphertext with other than 2 elements is not implemented");


		UnivariatePolynomialZp64 newc0 = encoder.transformSlots(polys.get(0), index);
		UnivariatePolynomialZp64 newc1 = encoder.transformSlots(polys.get(1), index);
		
		polys.clear();
		polys.add(newc0);
		polys.add(newc1);
	}

	
	
	/**
	 * Rekey this ciphertext from a rotation of the secret key back to the secret key
	 * 
	 * @param rk the key to use for rekeying
	 */
	void rotationRekey(FVRotationKey rk, FVEncoder encoder, int rotation)
	{
		if(!rk.params.equals(this.params)) 
			throw new RuntimeException("Ciphertext parameters in rotation key do not match");
		if(polys.size() != 2)
			throw new RuntimeException("Rekeying a ciphertext with other than 2 elements is not implemented");

		ArrayList< UnivariatePolynomialZp64 > decomp = PolynomialUtils.decomposePolynomial(polys.get(1), params.decompositionBase);
		
		UnivariatePolynomialZp64 newc0 =
				PolynomialUtils.accumulateDotProduct(params.ctPolyField, polys.get(0), rk.keys0.get(rotation), decomp);
		UnivariatePolynomialZp64 newc1 = 			
				PolynomialUtils.accumulateDotProduct(params.ctPolyField, polys.get(1), rk.keys1.get(rotation), decomp);
		
		polys.clear();
		polys.add(newc0);
		polys.add(newc1);
	}

}
