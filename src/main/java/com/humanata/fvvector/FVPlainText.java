/**
 * 
 */
package com.humanata.fvvector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;

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
	 * @throws RuntimeException if the data length does not match the encoder parameters
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
	 * @return decoded long array with the plaintext slot values
	 * @throws RuntimeException if the plaintext polynomial does not match encoder parameters
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
	 * @throws RuntimeException if the plaintext parameters do not match the public key
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

	/**
	 * Serialize this plaintext to a byte array.
	 *
	 * @return serialized plaintext bytes
	 */
	public byte[] toBytes()
	{
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DataOutputStream out = new DataOutputStream(baos);
			writeTo(out);
			out.flush();
			return baos.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException("Failed to serialize plaintext", e);
		}
	}

	/**
	 * Serialize this plaintext to a data output stream.
	 *
	 * @param out destination stream
	 * @throws IOException if the stream cannot be written
	 */
	public void writeTo(DataOutput out) throws IOException
	{
		FVSerialization.writePolynomial(encoding, out);
	}

	/**
	 * Deserialize a plaintext from a byte array.
	 *
	 * @param data serialized plaintext bytes
	 * @return deserialized plaintext
	 */
	public static FVPlainText fromBytes(byte[] data)
	{
		try {
			DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
			return readFrom(in);
		} catch (IOException e) {
			throw new RuntimeException("Failed to deserialize plaintext", e);
		}
	}

	/**
	 * Deserialize a plaintext from a data input stream.
	 *
	 * @param in source stream
	 * @return deserialized plaintext
	 * @throws IOException if the stream cannot be read
	 */
	public static FVPlainText readFrom(DataInput in) throws IOException
	{
		UnivariatePolynomialZp64 poly = FVSerialization.readPolynomial(in);
		FVPlainText pt = new FVPlainText();
		pt.set(poly);
		return pt;
	}
}
