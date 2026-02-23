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

import cc.redberry.rings.poly.univar.*;


/**
 * Represents the private key for the FV cryptosystem.
 * <p>
 * <b>For experimentation and learning only.</b> Not for production use.
 * This class supports serialization via {@code toBytes}/{@code fromBytes}.
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

	FVPrivateKey(FVParameters params, UnivariatePolynomialZp64 privateKeyPolynomial)
	{
		if(privateKeyPolynomial.ring.modulus != params.coefficientModulus)
			throw new RuntimeException("Private key polynomial modulus does not match parameters");
		this.params = params;
		this.privateKeyPolynomial = privateKeyPolynomial.clone();
	}
		
	UnivariatePolynomialZp64 key()
	{
		return privateKeyPolynomial;
	}

	/**
	 * Serialize this private key to a byte array.
	 *
	 * @return serialized private key bytes
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
			throw new RuntimeException("Failed to serialize private key", e);
		}
	}

	/**
	 * Serialize this private key to a data output stream.
	 *
	 * @param out destination stream
	 * @throws IOException if the stream cannot be written
	 */
	public void writeTo(DataOutput out) throws IOException
	{
		FVSerialization.writeParameters(params, out);
		FVSerialization.writePolynomial(privateKeyPolynomial, out);
	}

	/**
	 * Deserialize a private key from a byte array.
	 *
	 * @param data serialized private key bytes
	 * @return deserialized private key
	 */
	public static FVPrivateKey fromBytes(byte[] data)
	{
		try {
			DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
			return readFrom(in);
		} catch (IOException e) {
			throw new RuntimeException("Failed to deserialize private key", e);
		}
	}

	/**
	 * Deserialize a private key from a data input stream.
	 *
	 * @param in source stream
	 * @return deserialized private key
	 * @throws IOException if the stream cannot be read
	 */
	public static FVPrivateKey readFrom(DataInput in) throws IOException
	{
		FVParameters params = FVSerialization.readParameters(in);
		UnivariatePolynomialZp64 key = FVSerialization.readPolynomial(in, params.coefficientModulus);
		return new FVPrivateKey(params, key);
	}
		

}
