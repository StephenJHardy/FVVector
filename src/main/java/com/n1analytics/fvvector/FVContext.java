package com.n1analytics.fvvector;

import static cc.redberry.rings.Rings.GF;

import java.security.SecureRandom;

import static cc.redberry.rings.Rings.*;

import cc.redberry.rings.IntegersZp64;
import cc.redberry.rings.poly.FiniteField;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/** This class carries around the information required to manipulate 
 * ciphertexts using homomorphic arithmetic and offers convenient
 * 
 * @author har991
 *
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
	 * Encode a vector of longs into a plaintext according to the encryption
	 * parameters of this context.
	 * 
	 * @param data array of long data to be encrypted - throws on incorrect length
	 * @return a plaintext object with the data encoded in its slots
	 */
	FVPlainText encode(long[] data)
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
	 */
	long[] decode(FVPlainText pt)
	{
		return pt.decode(encoder);
	}
	
	/**
	 * Encrypt an encoded plaintext into a ciphertext using the public key associated with this context
	 * 
	 * @param pt plaintext to encrypte
	 * @return ciphertext with encrypted plaintext
	 */
	FVCipherText encrypt(FVPlainText pt)
	{
		return pt.encrypt(publicKey);
	}

	/**
	 * Encode and encrypt a given array of longs. Assumes the array is of correct length or will throw
	 * 
	 * @param data the data to encrypt
	 * @return a cipher text object with the encrypted data
	 */
	FVCipherText encrypt(long[] data)
	{
		return encode(data).encrypt(publicKey);
	}

	/**
	 * Decrypt a ciphertext to an encoded plaintext using the provided private key
	 * 
	 * @param ct ciphertext to decrypt
	 * @param pk private key to use
	 * @return a plaintext with data encoded in the slots
	 */
	FVPlainText decrypt(FVCipherText ct, FVPrivateKey pk)
	{
		return ct.decrypt(pk);
	}

	/**
	 * Decrypt and decode a ciphertext to an array of longs using the provided private key
	 * 
	 * @param ct ciphertext to decrypt and decode
	 * @param pk private key to use
	 * @return an array with the decoded data
	 */
	long[] decryptAndDecode(FVCipherText ct, FVPrivateKey pk)
	{
		return decode(decrypt(ct, pk));
	}
	
	/**
	 * Add two ciphertexts and return a new ciphertext with the result
	 * 
	 * @param ct1 first operand
	 * @param ct2 second operand
	 * @return new ciphertext with the result
	 */
	FVCipherText add(FVCipherText ct1, FVCipherText ct2)
	{
		FVCipherText ret = new FVCipherText(ct1);
		ret.addTo(ct2);
		return ret;
	}

	/**
	 * Multiply two ciphertexts and return a new ciphertext with the result
	 * 
	 * @param ct1 first operand
	 * @param ct2 second operand
	 * @return new ciphertext with the result
	 */
	FVCipherText multiply(FVCipherText ct1, FVCipherText ct2)
	{
		FVCipherText ret = new FVCipherText(ct1);
		ret.multiplyBy(ct2);
		return ret;
	}

	/**
	 * Multiply two ciphertexts and return a new reliearised ciphertext with the result
	 * 
	 * @param ct1 first operand
	 * @param ct2 second operand
	 * @return new ciphertext with the relinearised result
	 */
	FVCipherText multiplyAndRelinearise(FVCipherText ct1, FVCipherText ct2)
	{
		FVCipherText ret = new FVCipherText(ct1);
		ret.multiplyBy(ct2);
		ret.relineariseCubic(this.relinKey);
		return ret;
	}
	

	/**
	 * Treating a ciphertext as a N/2 x 2 matrix, swap the rows
	 * 
	 * @param input ciphertext to transform
	 * @return new ciphertext with transformed result
	 */
	FVCipherText interchangeSlotVectors(FVCipherText input)
	{
		FVCipherText ret = new FVCipherText(input);
		ret.rotate(encoder, encoder.interchangeIndex());
		ret.rotationRekey(rotKey, encoder, encoder.interchangeIndex());
		return ret;
	}

	/**
	 * Treating a ciphertext as a N/2 x 2 matrix, rotate the rows left
	 * 
	 * @param input ciphertext to transform
	 * @return new ciphertext with transformed result
	 */
	FVCipherText rotateSlotsLeft(FVCipherText input, int toLeft)
	{
		FVCipherText ret = new FVCipherText(input);
		ret.rotate(encoder, encoder.leftRotateIndex(toLeft));
		ret.rotationRekey(rotKey, encoder, encoder.leftRotateIndex(toLeft));
		return ret;
	}
	
	/**
	 * Treating a ciphertext as a N/2 x 2 matrix, rotate the rows right
	 * 
	 * @param input ciphertext to transform
	 * @return new ciphertext with transformed result
	 */
	FVCipherText rotateSlotsRight(FVCipherText input, int toRight)
	{
		FVCipherText ret = new FVCipherText(input);
		ret.rotate(encoder, encoder.rightRotateIndex(toRight));
		ret.rotationRekey(rotKey, encoder, encoder.rightRotateIndex(toRight));
		return ret;
	}

}
