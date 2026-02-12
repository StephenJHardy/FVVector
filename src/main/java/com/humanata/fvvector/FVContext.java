package com.humanata.fvvector;

import static cc.redberry.rings.Rings.GF;

import java.security.SecureRandom;

import static cc.redberry.rings.Rings.*;

import cc.redberry.rings.IntegersZp64;
import cc.redberry.rings.poly.FiniteField;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/**
 * Carries the information required to manipulate ciphertexts using homomorphic
 * arithmetic and offers a convenient API for encoding, encryption, decryption,
 * and operations such as addition, multiplication, and slot rotations.
 * <p>
 * <b>For experimentation and learning only.</b> Do not use in production or
 * security-critical systems. See {@link FVParameters} for security warnings.
 *
 * @author har991
 */
public class FVContext {

	public FVPublicKey publicKey;
	public FVRelinearisationKey relinKey;
	public FVRotationKey rotKey;
	private static final SecureRandom sec = new SecureRandom();
	private FVEncoder encoder;
	
	/**
	 * Builds a context that allows for encryption operations based
	 * on a private key that is supplied (and includes information
	 * about the encryption parameters used).
	 * 
	 * The private key information is not stored in the context.
	 * 
	 * @param privateKey
	 * @return context to allow encrypted operations to occur.
	 */
	public static FVContext BuildDefaultContext(FVPrivateKey privateKey)
	{
		FVParameters ps = privateKey.params;
		FVPublicKey pubKey = new FVPublicKey(privateKey);
		FVEncoder encoder = new FVEncoder(ps);
		FVRelinearisationKey relinKey = new FVRelinearisationKey(privateKey);
		FVRotationKey rotKey = new FVRotationKey(privateKey, encoder);
		FVContext context = new FVContext(pubKey, encoder, relinKey, rotKey); 
		return context;
	}
	
	/**
	 * 
	 * Class that combines the ability to encode data into a vector with a public key
	 * This class allows manipulations of ciphertexts, including multiplication and 
	 * addition, and relinearisation of ciphertexts
	 * 
	 * @param params Parameters of the crypto system
	 */
	FVContext(FVPublicKey publicKey, FVEncoder encoder, FVRelinearisationKey relinKey, FVRotationKey rotKey)
	{
		this.publicKey = publicKey;
		this.relinKey = relinKey;
		this.rotKey = rotKey;
		this.encoder = encoder;
	}

	/**
	 * Returns the encoder used by this context for encoding and decoding slot-packed vectors.
	 *
	 * @return the FVEncoder for this context's parameters
	 */
	public FVEncoder getEncoder()
	{
		return encoder;
	}

	
	/**
	 * Encode a vector of longs into a plaintext according to the encryption
	 * parameters of this context.
	 * 
	 * @param data array of long data to be encrypted - throws on incorrect length
	 * @return a plaintext object with the data encoded in its slots
	 * @throws RuntimeException if data length does not match the parameter set
	 */
	public FVPlainText encode(long[] data)
	{
		if(data.length != publicKey.params.polynomialModulusExponent)
			throw new RuntimeException("Data to encode has wrong length");
		FVPlainText ret = new FVPlainText();
		ret.encode(encoder, data);
		return ret;
	}

	
	/**
	 * Decode the data inside the given plaintext according to the encoding parameters 
	 * is the context.
	 * 
	 * @param pt  the plaintext to decode
	 * @return a long array with the values in the slots encoded in the plaintext
	 * @throws RuntimeException if the plaintext does not match the encoder parameters
	 */
	public long[] decode(FVPlainText pt)
	{
		return pt.decode(encoder);
	}
	
	/**
	 * Encrypt an encoded plaintext into a ciphertext using the public key associated with this context
	 * 
	 * @param pt plaintext to encrypt
	 * @return ciphertext with encrypted plaintext
	 * @throws RuntimeException if plaintext parameters do not match the public key
	 */
	public FVCipherText encrypt(FVPlainText pt)
	{
		return pt.encrypt(publicKey);
	}

	/**
	 * Encode and encrypt a given array of longs. Assumes the array is of correct length or will throw
	 * 
	 * @param data the data to encrypt
	 * @return a cipher text object with the encrypted data
	 * @throws RuntimeException if data length does not match the parameter set
	 */
	public FVCipherText encodeAndEncrypt(long[] data)
	{
		return encode(data).encrypt(publicKey);
	}

	/**
	 * Decrypt a ciphertext to an encoded plaintext using the provided private key
	 * 
	 * @param ct ciphertext to decrypt
	 * @param pk private key to use
	 * @return a plaintext with data encoded in the slots
	 * @throws RuntimeException if key parameters do not match the ciphertext parameters
	 */
	public FVPlainText decrypt(FVCipherText ct, FVPrivateKey pk)
	{
		return ct.decrypt(pk);
	}

	/**
	 * Decrypt and decode a ciphertext to an array of longs using the provided private key
	 * 
	 * @param ct ciphertext to decrypt and decode
	 * @param pk private key to use
	 * @return an array with the decoded data
	 * @throws RuntimeException if key parameters do not match the ciphertext parameters
	 */
	public long[] decryptAndDecode(FVCipherText ct, FVPrivateKey pk)
	{
		return decode(decrypt(ct, pk));
	}
	
	/**
	 * Add two ciphertexts and return a new ciphertext with the result
	 * 
	 * @param ct1 first operand
	 * @param ct2 second operand
	 * @return new ciphertext with the result
	 * @throws RuntimeException if ciphertext parameters do not match
	 */
	public FVCipherText add(FVCipherText ct1, FVCipherText ct2)
	{
		FVCipherText ret = new FVCipherText(ct1);
		ret.addTo(ct2);
		return ret;
	}

	/**
	 * Subtract the second ciphertext from the first and return a new ciphertext with the result
	 * 
	 * @param ct1 first operand
	 * @param ct2 second operand
	 * @return new ciphertext with the result
	 * @throws RuntimeException if ciphertext parameters do not match
	 */
	public FVCipherText subtract(FVCipherText ct1, FVCipherText ct2)
	{
		FVCipherText ret = new FVCipherText(ct1);
		ret.subtractFrom(ct2);
		return ret;
	}

	/**
	 * Multiply two ciphertexts and return a new ciphertext with the result
	 * 
	 * @param ct1 first operand
	 * @param ct2 second operand
	 * @return new ciphertext with the result
	 * @throws RuntimeException if ciphertext parameters do not match
	 */
	public FVCipherText multiplyWithoutRelinearisation(FVCipherText ct1, FVCipherText ct2)
	{
		FVCipherText ret = new FVCipherText(ct1);
		ret.multiplyBy(ct2);
		return ret;
	}

	/**
	 * Multiply two ciphertexts and return a new relinearised ciphertext with the result
	 * 
	 * @param ct1 first operand
	 * @param ct2 second operand
	 * @return new ciphertext with the relinearised result
	 * @throws RuntimeException if ciphertext parameters do not match
	 */
	public FVCipherText multiply(FVCipherText ct1, FVCipherText ct2)
	{
		FVCipherText ret = new FVCipherText(ct1);
		ret.multiplyBy(ct2);
		ret.relineariseCubic(this.relinKey);
		return ret;
	}
	
	/**
	 * Multiply a ciphertext by a plaintext and return a new ciphertext with the result.
	 * This does not require relinearisation.
	 * 
	 * @param ct1 first operand
	 * @param pt2 second operand
	 * @return new ciphertext with the result
	 * @throws RuntimeException if plaintext size does not match the ciphertext parameters
	 */
	public FVCipherText multiply(FVCipherText ct1, FVPlainText pt2)
	{
		FVCipherText ret = new FVCipherText(ct1);
		ret.multiplyBy(pt2);
		return ret;
	}

	/**
	 * Multiply a plaintext by a ciphertext and return a new ciphertext with the result.
	 * This does not require relinearisation.
	 * 
	 * @param pt1 first operand
	 * @param ct2 second operand
	 * @return new ciphertext with the result
	 * @throws RuntimeException if plaintext size does not match the ciphertext parameters
	 */
	public FVCipherText multiply(FVPlainText pt1, FVCipherText ct2)
	{
		FVCipherText ret = new FVCipherText(ct2);
		ret.multiplyBy(pt1);
		return ret;
	}
	
	/**
	 * Treating a ciphertext as a N/2 x 2 matrix, swap the rows
	 * 
	 * @param input ciphertext to transform
	 * @return new ciphertext with transformed result
	 * @throws RuntimeException if ciphertext is not a 2-element ciphertext
	 */
	public FVCipherText interchangeSlotVectors(FVCipherText input)
	{
		FVCipherText ret = new FVCipherText(input);
		ret.rotate(encoder, encoder.interchangeIndex());
		ret.rotationRekey(rotKey, encoder.interchangeIndex());
		return ret;
	}

	/**
	 * Treating a ciphertext as a N/2 x 2 matrix, rotate the rows left
	 * 
	 * @param input ciphertext to transform
	 * @return new ciphertext with transformed result
	 * @throws RuntimeException if ciphertext is not a 2-element ciphertext
	 */
	public FVCipherText rotateSlotsLeft(FVCipherText input, int toLeft)
	{
		FVCipherText ret = new FVCipherText(input);
		ret.rotate(encoder, encoder.leftRotateIndex(toLeft));
		ret.rotationRekey(rotKey, encoder.leftRotateIndex(toLeft));
		return ret;
	}
	
	/**
	 * Treating a ciphertext as a N/2 x 2 matrix, rotate the rows right
	 * 
	 * @param input ciphertext to transform
	 * @return new ciphertext with transformed result
	 * @throws RuntimeException if ciphertext is not a 2-element ciphertext
	 */
	public FVCipherText rotateSlotsRight(FVCipherText input, int toRight)
	{
		FVCipherText ret = new FVCipherText(input);
		ret.rotate(encoder, encoder.rightRotateIndex(toRight));
		ret.rotationRekey(rotKey, encoder.rightRotateIndex(toRight));
		return ret;
	}

	/**
	 * Sum all slot values into the first slot.
	 * The result ciphertext has the sum of all input slots in slot 0;
	 * other slots may contain arbitrary values.
	 *
	 * @param input ciphertext whose slots to sum
	 * @return new ciphertext with the sum in slot 0
	 * @throws RuntimeException if ciphertext is not a 2-element ciphertext
	 */
	public FVCipherText sumIntoFirstSlot(FVCipherText input)
	{
		FVCipherText ret = new FVCipherText(input);
		ret.sumIntoFirstSlot(rotKey);
		return ret;
	}

}
