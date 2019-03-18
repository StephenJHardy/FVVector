

## Introduction
FVVector is a java native library that implements the Fan-Vercauteren encryption system for homomorphic operations on vectors of integers. It has a simple API and is designed as a demonstration library that illustrates the concepts behind the scheme. 

## Hello World
Let's do a homomorphic multiplication of a vector of 1024 integers packed into a single ciphertext.

#### Setup
		FVParameters ps = FVParameters.FVParamsN1024S128;
		FVPrivateKey privKey = new FVPrivateKey(ps);
		FVContext context = FVContext.BuildDefaultContext(privKey);
		
#### Put some random numbers into vectors
		SecureRandom rand = new SecureRandom();

		//Put something into the vectors
		long data1[] = new long[(int)ps.polynomialModulusExponent];
		long data2[] = new long[(int)ps.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = ps.ptRing.modulus(rand.nextLong());
			data2[i] = ps.ptRing.modulus(rand.nextLong());
		}

#### Homomorphic arithmetic		
		FVCipherText ct1 = context.encrypt(data1);
		FVCipherText ct2 = context.encrypt(data2);
		FVCipherText ct3 = context.multiply(ct1, ct2);
		long datares[] = context.decryptAndDecode(ct3, privKey);

#### Prove it is correct
		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(ps.ptRing.modulus(data1[i] * data2[i]), 				
						 ps.ptRing.modulus(datares[i]));
		}

## Capabilities
The library as implemented allows the encryption of power of two vector lengths (>= 1024) numbers that are treated modulo a given plaintext modulus. These plaintexts can be encrypted and then the library allows
* addition of encrypted vectors
* multiplication of encrypted vectors
* certain rotations and permutations of the elements
* decryption of the vectors

As implemented, the library allows the use of moduli up to 63 bits in size. This limits the number of arithmetic and rotation operations that can be done while still allowing correct decryption of the results.

## Structure

Plaintexts and ciphertexts are represented as arrays of polynomials. As a first cut, we use [Redberry Rings](https://github.com/PoslavskySV/rings), a sophisticated polynomial ring library, to contain and manipulate these polynomials. All of the code that manipulates these objects is kept in *PolynomialUtils.java*.

The following objects are defined in the library for external use:

| Object | Use |
|--------|-----|
|FVParameters | Contains all the configuration information about the parameters of the cryptosystem and encoding |
| FVPrivateKey | Represents the private key |
| FVPublicKey | Represents the public key |
| FVEncoder | Enables encoding of numbers as plaintexts |
| FVPlainText | Represents an array of numbers encoded into a plaintext |
| FVCipherText | Represents an encrypted encoded array of numbers and allows their manipulation |
| FVRelinearisationKey | Enables the relinearisation of ciphertexts back to two elements |
| FVRotationKey | Enables permuted ciphertexts to be able to be decrypted |
| FVContext | Convenience object with simple API |



#### FVParameters

The basic information about the cryptosystem that is being used is contained in the **FVParameters** class. The parameters available are:
* number of bits of security
* number of elements encoded in a vector (must be a power of two)
* number of bits available to encode numbers as a plain text
* number of bits of headroom available for homomorphic operations

Setting these parameters can be quite complicated, so there are two convenience types declared that have convenient choices avilable:

**FVParameters.FVParamsN1024S128** - A conservative parameter set that gives 128 bits of security and 1024 vector size. Has 16 bits for the plaintext, 29 for the ciphertext, giving 13 bits of headroom. This is enough for encrypt/decrypt, but not enough for much arithmetic.
**FVParameters.FVParamsN2048S128** - A conservative parameter set that gives 128 bits of security and 2048 vector size. Has 32 bits for the plaintext, 56 for the ciphertext, giving 24 bits of headroom.


		
The parameters can then be used to create an **FVPrivateKey** which represents the private key.

### Simple approach
For convenience, an **FVContext** can be created from the private key, which uses the private key to generate various objects it needs (such as the public key) and then discards the private key. This context object has methods that expose all the capabilities of the cryptosystem such as encryption, decryption, addition, multiplication, and various vector manipulations.

| Task | FVContext method | description |
|------|------------------|-------------|
| encoding | encode | encode a long vector in a plaintext |
| decoding | decode | decode a plaintext to a long vector |
| encrypting | encrypt | encrypt a plaintext to a ciphertext |
| decrypting | decrypt | decrypt a ciphertext to a plaintext |
| encode and encrypt | encodeAndEncrypt | encode a vector of longs and encrypt to ciphertext |
| decrypt and decode | decryptAndDecode | decrypt a ciphertext and decode to a vector of longs |
| addition | add | add two ciphertexts |
| subtraction | subtract | subtract one cyphertext from another |
| multiplication | multiply | multiply two ciphertexts (and relinearise) |
| multiplication | multiply | multiply a ciphertext by a plaintext |
| slot permutation | interchangeSlotVectors | treat encrypted vector as two rows and swap rows |
| slot permutation | rotateSlotsLeft | treat encrypted vector as two rows and rotate rows left |
| slot permutation | rotateSlotsRight | treat encrypted vector as two rows and rotate rows right |


### Detailed approach
Rather than using the FVContext object to manipulate plaintexts and ciphertexts directly, it is possible to use the methods of the objects directly. Consult the javadocs for the classes for details.


## Performance
The library is written wholly in java and all polynomial manipulations in finite fields are done using the Redberry Rings java library. Due to this, several algorithmic optimisations that are used in other libraries have not been implemented (yet). These include representing the ciphertext polynomial coefficients in a residue number system (RNS), and also the use of the Number Theoretic Transform in performing polynomial multiplications. This means that this library is algorithmically slower than other implementations out there. However, because of this, it is significantly easier to understand 





