package com.humanata.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;

import com.humanata.fvvector.FVParameters.SecurityParam;
import org.junit.jupiter.api.BeforeAll;

class FVCipherTextTest {

	static FVParameters params;
	static FVPrivateKey priv;
	static FVPublicKey pub;
	static FVEncoder encoder;

	@BeforeAll
	public static void preClassSetup()
	{
		// Insecure parameters for faster tests; do not use in production.
		params = FVParameters.FVParamsN1024S128insecure;
		priv = new FVPrivateKey(params);
		pub = new FVPublicKey(priv);
		encoder = new FVEncoder(params);
	}

	@Test
	void testFVCipherTextFVParameters() {
		FVCipherText ct = new FVCipherText(params);
		assertSame(params, ct.params);
	}

	@Test
	void testFVCipherTextFVCipherText() {

		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = params.ptRing.modulus(rand.nextLong());
		}
		
		FVPlainText pt1 = new FVPlainText();
		pt1.encode(encoder, data1);
		FVCipherText ct1 = pt1.encrypt(pub);
		
		FVCipherText ct2 = new FVCipherText(ct1);
		
		assertEquals(ct1.polys.get(0).toString(), ct2.polys.get(0).toString());
		
		
	}

	@Test
	public void testMeasureCTNoise() throws Exception {
		

		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		long data2[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = params.ptRing.modulus(rand.nextLong());
			data2[i] = params.ptRing.modulus(rand.nextLong());
		}
		
		FVPlainText pt1 = new FVPlainText();
		pt1.encode(encoder, data1);
		FVCipherText ct1 = pt1.encrypt(pub);
		
		FVPlainText pt2 = new FVPlainText();
		pt2.encode(encoder, data2);
		FVCipherText ct2 = pt2.encrypt(pub);

		double n1 = ct1.measureCTNoise(priv);
		double n2 = ct2.measureCTNoise(priv);

		ct2.addTo(ct1);
		double n3 = ct2.measureCTNoise(priv);
		
		assertTrue(n1 < 0.1);
		assertTrue(n2 < 0.1);
		assertTrue(n3 < 0.1);
	}

	@Test
	void testDecrypt() {

		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = params.ptRing.modulus(rand.nextLong());
		}
		
		FVPlainText pt1 = new FVPlainText();
		pt1.encode(encoder, data1);
		FVCipherText ct1 = pt1.encrypt(pub);

		FVParameters params2 = FVParameters.FVParamsN2048S128;
		FVPrivateKey priv2 = new FVPrivateKey(params2);

		assertThrows(RuntimeException.class, () -> { ct1.decrypt(priv2); });
	}

//	@Test
//	void testSet() {
//		fail("Not yet implemented");
//	}
//
	@Test
	void testAddTo() {

		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		long data2[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = params.ptRing.modulus(rand.nextLong());
			data2[i] = params.ptRing.modulus(rand.nextLong());
		}
		
		FVPlainText pt1 = new FVPlainText();
		pt1.encode(encoder, data1);
		FVCipherText ct1 = pt1.encrypt(pub);
		
		FVPlainText pt2 = new FVPlainText();
		pt2.encode(encoder, data2);
		FVCipherText ct2 = pt2.encrypt(pub);

		ct2.addTo(ct1);
		FVPlainText pt3 = ct2.decrypt(priv);
		long datares[] = pt3.decode(encoder);

		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(params.ptRing.modulus(data1[i] + data2[i]), params.ptRing.modulus(datares[i]));
		}
	}

	@Test
	void testSubtractFrom() {
		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		long data2[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = params.ptRing.modulus(rand.nextLong());
			data2[i] = params.ptRing.modulus(rand.nextLong());
		}
		
		FVPlainText pt1 = new FVPlainText();
		pt1.encode(encoder, data1);
		FVCipherText ct1 = pt1.encrypt(pub);
		
		FVPlainText pt2 = new FVPlainText();
		pt2.encode(encoder, data2);
		FVCipherText ct2 = pt2.encrypt(pub);

		ct1.subtractFrom(ct2);
		FVPlainText pt3 = ct1.decrypt(priv);
		long datares[] = pt3.decode(encoder);

		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(params.ptRing.modulus(data1[i] - data2[i]), params.ptRing.modulus(datares[i]));
		}
	}

	
	@Test
	void testMultiplyBy() {

		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		long data2[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = rand.nextLong() % 10;
			data2[i] = rand.nextLong() % 10;
		}
		
		FVPlainText pt1 = new FVPlainText();
		pt1.encode(encoder, data1);
		FVCipherText ct1 = pt1.encrypt(pub);

		FVPlainText pt2 = new FVPlainText();
		pt2.encode(encoder, data2);
		FVCipherText ct2 = pt2.encrypt(pub);

		ct2.multiplyBy(ct1);

		assertEquals(3, ct2.size());
		assertEquals(params.polynomialModulusExponent, ct2.polys.get(0).size());
		FVPlainText pt3 = ct2.decrypt(priv);
		long datares[] = pt3.decode(encoder);

		
		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(params.ptRing.modulus(data1[i] * data2[i]), params.ptRing.modulus(datares[i]));
		}
		
	}

	@Test
	void testMultiplyByPlaintext() {

		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		long data2[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = rand.nextLong() % 10;
			data2[i] = rand.nextLong() % 10;
		}
		
		FVPlainText pt1 = new FVPlainText();
		pt1.encode(encoder, data1);
		FVCipherText ct1 = pt1.encrypt(pub);

		FVPlainText pt2 = new FVPlainText();
		pt2.encode(encoder, data2);

		ct1.multiplyBy(pt2);

		assertEquals(2, ct1.size());
		assertEquals(params.polynomialModulusExponent, ct1.polys.get(0).size());
		FVPlainText pt3 = ct1.decrypt(priv);
		long datares[] = pt3.decode(encoder);

		
		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(params.ptRing.modulus(data1[i] * data2[i]), params.ptRing.modulus(datares[i]));
		}
		
	}

	
	@Test
	public void testRelineariseCubic() throws Exception {

		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		long data2[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = rand.nextLong() % 10;
			data2[i] = rand.nextLong() % 10;
		}
		
		FVPlainText pt1 = new FVPlainText();
		pt1.encode(encoder, data1);
		FVCipherText ct1 = pt1.encrypt(pub);
		
		FVPlainText pt2 = new FVPlainText();
		pt2.encode(encoder, data2);
		FVCipherText ct2 = pt2.encrypt(pub);
		ct2.multiplyBy(ct1);

		FVRelinearisationKey rk = new FVRelinearisationKey(priv);		
		ct2.relineariseCubic(rk);

		assertEquals(2, ct2.size());
		FVPlainText pt4 = ct2.decrypt(priv);
		long dataresrelin[] = pt4.decode(encoder);
		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(params.ptRing.modulus(data1[i] * data2[i]), params.ptRing.modulus(dataresrelin[i]));
		}
			
	}

	@Test
	@Tag("slow")
	public void testRotate() throws Exception {
		FVRotationKey rotKey = new FVRotationKey(priv, encoder);
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = i;
		}
		
		FVPlainText pt1 = new FVPlainText();
		pt1.encode(encoder, data1);
		
		FVCipherText ct1 = pt1.encrypt(pub);

		FVCipherText ct2 = new FVCipherText(ct1);
		ct2.rotate(encoder, encoder.interchangeIndex());
		ct2.rotationRekey(rotKey, encoder.interchangeIndex());
		
		long[] decoded1 = ct1.decrypt(priv).decode(encoder);
		long[] decoded2 = ct2.decrypt(priv).decode(encoder);
		
		for(int i = 0; i < data1.length/2; i++)
		{
			assertEquals(decoded1[i],decoded2[i + data1.length/2]); 
			assertEquals(decoded1[i + data1.length/2], decoded2[i]);  	
		}
	}

}
