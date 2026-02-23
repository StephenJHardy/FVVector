package com.humanata.fvvector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.stream.IntStream;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/**
 *
 * This class represents a set of keys for the FV cryptosystem that allows a ciphertext
 * with three elements to be reduced to a ciphertext with only two elements, at the expense
 * of some additional noise in the ciphertext.
 * It supports serialization via {@code toBytes}/{@code fromBytes}.
 *
 * @author har991
 *
 */

public class FVRelinearisationKey {

	private static final int PARALLEL_KEY_THRESHOLD = Integer.getInteger(
			"fvvector.parallelRelinKeyThreshold", 4);
	private static final boolean PARALLEL_DISABLED = Boolean.getBoolean("fvvector.disableParallel");

	// Each relinearisation key is represented by a set of two polynomials
	// These polynomials represented masked noisy versions of the square of the 
	// secret key.
	
	ArrayList< UnivariatePolynomialZp64 > polys0 = new ArrayList< UnivariatePolynomialZp64 >();
	ArrayList< UnivariatePolynomialZp64 > polys1 = new ArrayList< UnivariatePolynomialZp64 >();

	FVParameters params;

	/**
	 * 
	 * Construct a relinearisation key from a private key.
	 * 
	 * @param privKey the private key to generate the public key from
	 * 
	 */
	public FVRelinearisationKey(FVPrivateKey privKey)
	{
		this.params = privKey.params;
		UnivariatePolynomialZp64 s2 = privKey.params.ctPolyField.multiply(privKey.key(), privKey.key());
		
		int elements = (int) params.l + 1;
		if (shouldParallel(elements))
		{
			UnivariatePolynomialZp64[] local0 = new UnivariatePolynomialZp64[elements];
			UnivariatePolynomialZp64[] local1 = new UnivariatePolynomialZp64[elements];

			IntStream.range(0, elements).parallel().forEach(i -> {
				UnivariatePolynomialZp64 a = privKey.params.generaateUniformCTPolynomial();
				UnivariatePolynomialZp64 e = privKey.params.generateNoiseCTPolynomial();

				UnivariatePolynomialZp64 r =
						privKey.params.ctPolyField.add(
							privKey.params.ctPolyField.negate(
								privKey.params.ctPolyField.add(
									privKey.params.ctPolyField.multiply(a, privKey.key())
									,  e
								)
							),
							privKey.params.ctPolyField.multiply(s2, (long)Math.pow(params.decompositionBase, i))
						);

				local0[i] = r;
				local1[i] = a;
			});

			for (int i = 0; i < elements; i++) {
				polys0.add(local0[i]);
				polys1.add(local1[i]);
			}
		}
		else
		{
			for(long i=0; i <= params.l; i++)
			{
				UnivariatePolynomialZp64 a = privKey.params.generaateUniformCTPolynomial();
				UnivariatePolynomialZp64 e = privKey.params.generateNoiseCTPolynomial();
			
				UnivariatePolynomialZp64 r =
						privKey.params.ctPolyField.add(
							privKey.params.ctPolyField.negate(
								privKey.params.ctPolyField.add( 
									privKey.params.ctPolyField.multiply(a, privKey.key())
									,  e
								)
							),
							privKey.params.ctPolyField.multiply(s2, (long)Math.pow(params.decompositionBase, i))
						);

				polys0.add(r);
				polys1.add(a);	
			}
		}
	}

	FVRelinearisationKey(FVParameters params,
			ArrayList< UnivariatePolynomialZp64 > polys0,
			ArrayList< UnivariatePolynomialZp64 > polys1)
	{
		if(polys0.size() != polys1.size())
			throw new RuntimeException("Relinearisation key polynomial list sizes do not match");
		if(polys0.size() != params.l + 1)
			throw new RuntimeException("Relinearisation key polynomial list has incorrect size");
		this.params = params;
		this.polys0 = polys0;
		this.polys1 = polys1;
	}

	/**
	 * Serialize this relinearisation key to a byte array.
	 *
	 * @return serialized relinearisation key bytes
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
			throw new RuntimeException("Failed to serialize relinearisation key", e);
		}
	}

	/**
	 * Serialize this relinearisation key to a data output stream.
	 *
	 * @param out destination stream
	 * @throws IOException if the stream cannot be written
	 */
	public void writeTo(DataOutput out) throws IOException
	{
		FVSerialization.writeParameters(params, out);
		FVSerialization.writePolynomialList(polys0, out);
		FVSerialization.writePolynomialList(polys1, out);
	}

	/**
	 * Deserialize a relinearisation key from a byte array.
	 *
	 * @param data serialized relinearisation key bytes
	 * @return deserialized relinearisation key
	 */
	public static FVRelinearisationKey fromBytes(byte[] data)
	{
		try {
			DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
			return readFrom(in);
		} catch (IOException e) {
			throw new RuntimeException("Failed to deserialize relinearisation key", e);
		}
	}

	/**
	 * Deserialize a relinearisation key from a data input stream.
	 *
	 * @param in source stream
	 * @return deserialized relinearisation key
	 * @throws IOException if the stream cannot be read
	 */
	public static FVRelinearisationKey readFrom(DataInput in) throws IOException
	{
		FVParameters params = FVSerialization.readParameters(in);
		ArrayList< UnivariatePolynomialZp64 > polys0 = FVSerialization.readPolynomialList(in, params.coefficientModulus);
		ArrayList< UnivariatePolynomialZp64 > polys1 = FVSerialization.readPolynomialList(in, params.coefficientModulus);
		return new FVRelinearisationKey(params, polys0, polys1);
	}

	private static boolean shouldParallel(int elementCount)
	{
		if (PARALLEL_DISABLED) {
			return false;
		}
		if (elementCount < PARALLEL_KEY_THRESHOLD) {
			return false;
		}
		if (ForkJoinTask.inForkJoinPool()) {
			return false;
		}
		return ForkJoinPool.getCommonPoolParallelism() > 1;
	}
	
	
}
