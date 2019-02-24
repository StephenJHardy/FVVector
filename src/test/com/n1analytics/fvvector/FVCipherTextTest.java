package com.n1analytics.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

import com.n1analytics.fvvector.FVParameters.SecurityParam;

class FVCipherTextTest {

	@Test
	void testFVCipherTextFVParameters() {
		FVParameters params = FVParameters.FVParamsN1024S128;
		FVCipherText ct = new FVCipherText(params);
		assertSame(params, ct.params);
	}

	@Test
	void testFVCipherTextFVCipherText() {
		FVParameters params = FVParameters.FVParamsN1024S128;
		
		FVPrivateKey priv = new FVPrivateKey(params);
		FVPublicKey pub = new FVPublicKey(priv);
		FVEncoder encoder = new FVEncoder(params);

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
		
		//FVParameters params = FVParameters.FVParamsN2048S128;
		FVParameters params = FVParameters.FVParamsN1024S128;
		
		FVPrivateKey priv = new FVPrivateKey(params);
		FVPublicKey pub = new FVPublicKey(priv);
		FVEncoder encoder = new FVEncoder(params);

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
		
		FVParameters params = FVParameters.FVParamsN1024S128;
		FVPrivateKey priv = new FVPrivateKey(params);
		FVPublicKey pub = new FVPublicKey(priv);
		FVEncoder encoder = new FVEncoder(params);

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
		FVParameters params = FVParameters.FVParamsN1024S128;
		
		FVPrivateKey priv = new FVPrivateKey(params);
		FVPublicKey pub = new FVPublicKey(priv);
		FVEncoder encoder = new FVEncoder(params);

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
	void testMultiplyBy() {
		FVParameters params = FVParameters.generateParameterSet(FVParameters.SecurityParam.BITS_128, 2048, 14, 56-14);
		FVPrivateKey priv = new FVPrivateKey(params);
		FVPublicKey pub = new FVPublicKey(priv);
		FVEncoder encoder = new FVEncoder(params);

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
		double r0 = ct1.measureCTNoise(priv);
		
		FVPlainText pt2 = new FVPlainText();
		pt2.encode(encoder, data2);
		FVCipherText ct2 = pt2.encrypt(pub);

		double r1 = ct2.measureCTNoise(priv);
		ct2.multiplyBy(ct1);
		
		double r2 = ct2.measureCTNoise(priv);
		System.out.println("Noise before: " + r1);
		System.out.println("Noise after: " + r2);
		
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
	public void testRelineariseCubic() throws Exception {
		FVParameters params = FVParameters.FVParamsN2048S128insecure;
		FVPrivateKey priv = new FVPrivateKey(params);
		FVPublicKey pub = new FVPublicKey(priv);
		FVEncoder encoder = new FVEncoder(params);

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
		double r3 = ct2.measureCTNoise(priv);
		System.out.println("Noise after relin: " + r3);
		
		assertEquals(2, ct2.size());
		FVPlainText pt4 = ct2.decrypt(priv);
		long dataresrelin[] = pt4.decode(encoder);
		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(params.ptRing.modulus(data1[i] * data2[i]), params.ptRing.modulus(dataresrelin[i]));
		}
			
	}

}
