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
import java.util.ArrayList;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/**
 * Represents a public key for the FV cryptosystem as a pair of polynomials
 * ([−(as + e)]q , a) where s is the secret key, a is random, and e is noise.
 * <p>
 * <b>For experimentation and learning only.</b> Not for production use.
 * This class supports serialization via {@code toBytes}/{@code fromBytes}.
 *
 * @author har991
 */
public class FVPublicKey {
	ArrayList< UnivariatePolynomialZp64 > polys = new ArrayList< UnivariatePolynomialZp64 >();

	FVParameters params;
	/**
	 * 
	 * Construct a public key from a private key.
	 * 
	 * @param privKey the private key to generate the public key from
	 * 
	 */
	public FVPublicKey(FVPrivateKey privKey)
	{
		this.params = privKey.params;
		
		UnivariatePolynomialZp64 a = privKey.params.generaateUniformCTPolynomial();
		UnivariatePolynomialZp64 e = privKey.params.generateNoiseCTPolynomial();
		
		UnivariatePolynomialZp64 r = 				
			privKey.params.ctPolyField.negate(
				privKey.params.ctPolyField.add( 
					privKey.params.ctPolyField.multiply(a, privKey.key())
					,  e
				)
			);

		polys.add(r);
		polys.add(a);	
	}

	FVPublicKey(FVParameters params, UnivariatePolynomialZp64 poly0, UnivariatePolynomialZp64 poly1)
	{
		if(poly0.ring.modulus != params.coefficientModulus || poly1.ring.modulus != params.coefficientModulus)
			throw new RuntimeException("Public key polynomial modulus does not match parameters");
		this.params = params;
		polys.add(poly0.clone());
		polys.add(poly1.clone());
	}
	
	
	/**
	 * Get the first element of the key
	 * @return a polynomial representing the first element of the key
	 */
	UnivariatePolynomialZp64 e0()
	{
		return polys.get(0);
	}

	/**
	 * Get the second element of the key
	 * @return a polynomial representing the second element of the key
	 */
	UnivariatePolynomialZp64 e1()
	{
		return polys.get(1);
	}

	/**
	 * Serialize this public key to a byte array.
	 *
	 * @return serialized public key bytes
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
			throw new RuntimeException("Failed to serialize public key", e);
		}
	}

	/**
	 * Serialize this public key to a data output stream.
	 *
	 * @param out destination stream
	 * @throws IOException if the stream cannot be written
	 */
	public void writeTo(DataOutput out) throws IOException
	{
		FVSerialization.writeParameters(params, out);
		FVSerialization.writePolynomialList(polys, out);
	}

	/**
	 * Deserialize a public key from a byte array.
	 *
	 * @param data serialized public key bytes
	 * @return deserialized public key
	 */
	public static FVPublicKey fromBytes(byte[] data)
	{
		try {
			DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
			return readFrom(in);
		} catch (IOException e) {
			throw new RuntimeException("Failed to deserialize public key", e);
		}
	}

	/**
	 * Deserialize a public key from a data input stream.
	 *
	 * @param in source stream
	 * @return deserialized public key
	 * @throws IOException if the stream cannot be read
	 */
	public static FVPublicKey readFrom(DataInput in) throws IOException
	{
		FVParameters params = FVSerialization.readParameters(in);
		ArrayList<UnivariatePolynomialZp64> polys = FVSerialization.readPolynomialList(in, params.coefficientModulus);
		if (polys.size() != 2) {
			throw new IOException("Public key must contain exactly 2 polynomials");
		}
		return new FVPublicKey(params, polys.get(0), polys.get(1));
	}

}
