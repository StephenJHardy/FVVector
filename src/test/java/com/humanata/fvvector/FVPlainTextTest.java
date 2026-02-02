package com.humanata.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

class FVPlainTextTest {

	@Test
	void testEncodeDecode() {
		FVParameters params = FVParameters.FVParamsN1024S128;
		
		FVPrivateKey priv = new FVPrivateKey(params);
		FVPublicKey pub = new FVPublicKey(priv);
		FVEncoder encoder = new FVEncoder(params);

		SecureRandom rand = new SecureRandom();
		
		long data[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data.length; i++)
		{
			data[i] = params.ptRing.modulus(rand.nextLong());
		}
		
		FVPlainText pt = new FVPlainText();
		pt.encode(encoder, data);
		
		long data2[] = pt.decode(encoder);
		for(int i = 0; i < data2.length; i++)
		{
			assertEquals(data[i],data2[i]);
		}

	}

//	@Test
//	public void testSet() throws Exception {
//		FVPlainText pt = new FVPlainText();
//		
//	}

	
	@Test
	public void testEncryptDecrypt() throws Exception {
		FVParameters params = FVParameters.FVParamsN1024S128;
		
		FVPrivateKey priv = new FVPrivateKey(params);
		FVPublicKey pub = new FVPublicKey(priv);
		FVEncoder encoder = new FVEncoder(params);

		SecureRandom rand = new SecureRandom();
		
		long data[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data.length; i++)
		{
			data[i] = params.ptRing.modulus(rand.nextLong());
		}
		
		FVPlainText pt = new FVPlainText();
		pt.encode(encoder, data);

		FVCipherText ct = pt.encrypt(pub);
		
		FVPlainText pt2 = ct.decrypt(priv);
		long data2[] = pt2.decode(encoder);
		
		for(int i = 0; i < data2.length; i++)
			assertEquals(data[i], data2[i]);
		
	}

}
