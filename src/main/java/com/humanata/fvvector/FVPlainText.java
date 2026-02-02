/**
 * 
 */
package com.humanata.fvvector;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/**
 * 
 * This class represents a plaintext vector of longs, encoded according to the encoder specified on encoding. 
 * It enables encryption of the plaintext given a public key.
 * 
 * @author har991
 *
 */
public class FVPlainText {
	
	
	/**
	 *  the plaintext encoded as a polynomial
	 */
	UnivariatePolynomialZp64 encoding;
	
	
	/**
	 *  Default constructor for a plaintext - consistency is enforced during operations.
	 */
	public FVPlainText()
	{
	}
	
	/**
	 * Encode some data into this object. 
	 * 
	 * Consistency between the size of the data and the encoder parameters is checked within the encoder
	 * 
	 * @param encoder the encoder used to encode the long data into a polynomial
	 * @param data the data to encode
	 */
	public void encode(FVEncoder encoder, long[] data)
	{
		encoding = encoder.encode(data);
	}
	
	
	/**
	 * Decode some data from this object.
	 * 
	 * Consistency between the size of the polynomial and the encoder parameters is checked within the encoder
	 * 
	 * @param encoder the encoder to use for the decoding
	 * @return
	 */
	public long[] decode(FVEncoder encoder)
	{
		return encoder.decode(encoding);
	}
	
	
	/**
	 * Convenience function for setting the polynomial - probably unnecessary as it is at package scope
	 * 
	 * Does a deep copy of the input polynomial
	 * 
	 * @param in the polynomial to copy into this object.
	 */
	void set(UnivariatePolynomialZp64 in)
	{
		encoding = in.clone();
	}
	
	/**
	 * Turns a plaintext into a ciphertext given a public key.
	 * 
	 * Enforces that the parameters match or throws otherwise
	 * 
	 * @param pubKey public key to use for the encryption
	 * @return a FVCipherText with the encrypted data in it
	 * 
	 */
	public FVCipherText encrypt(FVPublicKey pubKey)
	{
		if((pubKey.params.maxPolynomialExponent < encoding.size()) ||
				(pubKey.params.plainTextModulus != encoding.ring.modulus))
			throw new RuntimeException("Mismatched parameters between plaintext and publickey");
		
		UnivariatePolynomialZp64 u = pubKey.params.generateSmallCTPolynomial();
		UnivariatePolynomialZp64 e1 = pubKey.params.generateNoiseCTPolynomial();
		UnivariatePolynomialZp64 e2 = pubKey.params.generateNoiseCTPolynomial();
		
		long delta = pubKey.params.coefficientModulus / pubKey.params.plainTextModulus;
		// ct = ([∆m + p0u + e1]q, [p1u + e2]q)
		UnivariatePolynomialZp64 field0 = 
				pubKey.params.ctPolyField.add(
						pubKey.params.ctPolyField.multiply(encoding.setModulus(u.ring), delta),
						pubKey.params.ctPolyField.multiply(pubKey.polys.get(0), u),
						e1
					);
		
		UnivariatePolynomialZp64 field1 = 
				pubKey.params.ctPolyField.add(
						pubKey.params.ctPolyField.multiply(pubKey.polys.get(1), u),
						e2
					);
		FVCipherText ret = new FVCipherText(pubKey.params);
		ret.set(field0,  field1);
		return ret;
	}
}
