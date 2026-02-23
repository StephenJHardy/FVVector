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
 * Represents a set of rotation keys for the FV cryptosystem that allow
 * slot rotations and permutations to be rekeyed back to the original secret key.
 * It supports serialization via {@code toBytes}/{@code fromBytes}.
 *
 * @author har991
 */

public class FVRotationKey {

	private static final int PARALLEL_KEY_THRESHOLD = Integer.getInteger(
			"fvvector.parallelRotationKeyThreshold", 16);
	private static final boolean PARALLEL_DISABLED = Boolean.getBoolean("fvvector.disableParallel");

	FVParameters params;
	private final FVEncoder encoder;

	private ArrayList< ArrayList< UnivariatePolynomialZp64 > > keys0;
	private ArrayList< ArrayList< UnivariatePolynomialZp64 > > keys1;

	/**
	 * 
	 * Construct a set of rotation keys from a private key and an encoder.
	 * 
	 * @param privKey the private key to generate the public key from
	 * @param encoder the encoder used to compute rotation indices
	 * @throws RuntimeException if private key and encoder parameters do not match
	 * 
	 */
	public FVRotationKey(FVPrivateKey privKey, FVEncoder encoder)
	{
		if(privKey.params != encoder.params)
			throw new RuntimeException("parameters must match in inputs to FVRotationKey constructor");
		
		this.params = privKey.params;
		this.encoder = encoder;

		int keyCount = numberOfKeys();
		int elements = elementsPerKey();
		keys0 = new ArrayList< ArrayList< UnivariatePolynomialZp64 > >(keyCount);
		keys1 = new ArrayList< ArrayList< UnivariatePolynomialZp64 > >(keyCount);

		if (shouldParallel(keyCount))
		{
			@SuppressWarnings("unchecked")
			ArrayList<UnivariatePolynomialZp64>[] local0 = new ArrayList[keyCount];
			@SuppressWarnings("unchecked")
			ArrayList<UnivariatePolynomialZp64>[] local1 = new ArrayList[keyCount];

			IntStream.range(0, keyCount).parallel().forEach(k -> {
				ArrayList<UnivariatePolynomialZp64> k0 = new ArrayList<UnivariatePolynomialZp64>(elements);
				ArrayList<UnivariatePolynomialZp64> k1 = new ArrayList<UnivariatePolynomialZp64>(elements);

				UnivariatePolynomialZp64 srot =
						PolynomialUtils.coeffTransform(privKey.key().clone(),
								encoder.generatorPowers[k],
								params.polynomialModulusExponent);
				UnivariatePolynomialZp64 smod =
						privKey.params.ctPolyField.add(
								privKey.params.ctPolyField.negate(privKey.key()),
								srot);

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
								privKey.params.ctPolyField.multiply(smod, (long)Math.pow(params.decompositionBase, i))
							);

					k0.add(r.copy());
					k1.add(a.copy());
				}

				local0[k] = k0;
				local1[k] = k1;
			});

			for (int k = 0; k < keyCount; k++) {
				keys0.add(local0[k]);
				keys1.add(local1[k]);
			}
		}
		else
		{
			for(int k = 0; k < keyCount; k++)
			{
				keys0.add(new ArrayList< UnivariatePolynomialZp64 > (elements));
				keys1.add(new ArrayList< UnivariatePolynomialZp64 > (elements));

				UnivariatePolynomialZp64 srot =
						PolynomialUtils.coeffTransform(privKey.key().clone(),
								encoder.generatorPowers[k],
								params.polynomialModulusExponent);
				UnivariatePolynomialZp64 smod =
						privKey.params.ctPolyField.add(
								privKey.params.ctPolyField.negate(privKey.key()),
								srot);

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
								privKey.params.ctPolyField.multiply(smod, (long)Math.pow(params.decompositionBase, i))
							);

					keys0.get(k).add(r.copy());
					keys1.get(k).add(a.copy());
				}
			}
		}
	}

	FVRotationKey(FVParameters params,
			FVEncoder encoder,
			ArrayList< ArrayList< UnivariatePolynomialZp64 > > keys0,
			ArrayList< ArrayList< UnivariatePolynomialZp64 > > keys1)
	{
		int expectedKeys = (int) params.polynomialModulusExponent / 2 + 1;
		int expectedElements = (int) params.l + 1;
		if(keys0.size() != expectedKeys || keys1.size() != expectedKeys)
			throw new RuntimeException("Rotation key list has incorrect size");
		for (int i = 0; i < expectedKeys; i++) {
			if (keys0.get(i).size() != expectedElements || keys1.get(i).size() != expectedElements) {
				throw new RuntimeException("Rotation key element list has incorrect size");
			}
		}
		this.params = params;
		this.encoder = encoder;
		this.keys0 = keys0;
		this.keys1 = keys1;
	}

	public int numberOfKeys()
	{
		return (int)params.polynomialModulusExponent/2 + 1;
	}

	public int elementsPerKey()
	{
		return (int)params.l + 1;
	}

	private static boolean shouldParallel(int keyCount)
	{
		if (PARALLEL_DISABLED) {
			return false;
		}
		if (keyCount < PARALLEL_KEY_THRESHOLD) {
			return false;
		}
		if (ForkJoinTask.inForkJoinPool()) {
			return false;
		}
		return ForkJoinPool.getCommonPoolParallelism() > 1;
	}

	/**
	 * Returns the encoder used by this rotation key for slot transformations.
	 *
	 * @return the FVEncoder associated with this rotation key
	 */
	public FVEncoder getEncoder()
	{
		return encoder;
	}

	/**
	 *
	 * Return the set of polynomials used to rekey the first element of a ciphertext that has been transformed by
	 * the given index.
	 *
	 * @param index the index of the transformation used (as implemented in the encoder class)
	 * @return an array list of polynomials with the correction factors
	 *
	 */
	public ArrayList< UnivariatePolynomialZp64 > getFirstRekeyingPolynomials(int index)
	{
		return keys0.get(index);
	}

	/**
	 *
	 * Return the set of polynomials used to rekey the second element of a ciphertext that has been transformed by
	 * the given index.
	 *
	 * @param index the index of the transformation used (as implemented in the encoder class)
	 * @return an array list of polynomials with the correction factors
	 *
	 */
	public ArrayList< UnivariatePolynomialZp64 > getSecondRekeyingPolynomials(int index)
	{
		return keys1.get(index);
	}

	/**
	 * Serialize this rotation key to a byte array.
	 *
	 * @return serialized rotation key bytes
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
			throw new RuntimeException("Failed to serialize rotation key", e);
		}
	}

	/**
	 * Serialize this rotation key to a data output stream.
	 *
	 * @param out destination stream
	 * @throws IOException if the stream cannot be written
	 */
	public void writeTo(DataOutput out) throws IOException
	{
		FVSerialization.writeParameters(params, out);
		FVSerialization.writePolynomial2dList(keys0, out);
		FVSerialization.writePolynomial2dList(keys1, out);
	}

	/**
	 * Deserialize a rotation key from a byte array.
	 *
	 * @param data serialized rotation key bytes
	 * @return deserialized rotation key
	 */
	public static FVRotationKey fromBytes(byte[] data)
	{
		try {
			DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
			return readFrom(in);
		} catch (IOException e) {
			throw new RuntimeException("Failed to deserialize rotation key", e);
		}
	}

	/**
	 * Deserialize a rotation key from a data input stream.
	 *
	 * @param in source stream
	 * @return deserialized rotation key
	 * @throws IOException if the stream cannot be read
	 */
	public static FVRotationKey readFrom(DataInput in) throws IOException
	{
		FVParameters params = FVSerialization.readParameters(in);
		FVEncoder encoder = new FVEncoder(params);
		ArrayList< ArrayList< UnivariatePolynomialZp64 > > keys0 =
				FVSerialization.readPolynomial2dList(in, params.coefficientModulus);
		ArrayList< ArrayList< UnivariatePolynomialZp64 > > keys1 =
				FVSerialization.readPolynomial2dList(in, params.coefficientModulus);
		return new FVRotationKey(params, encoder, keys0, keys1);
	}

}
