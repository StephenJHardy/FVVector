package com.n1analytics.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

class FVVectorTest {

	@Test
	void testEncryptDecrypt() {
		
		FVParameters ps = FVParameters.FVParamsN1024S128;
		FVContext pg = new FVContext(ps);
		FVPrivateKey privKey = new FVPrivateKey(pg);
		
		FVPublicKey pubKey = new FVPublicKey(pg, privKey);
		
		long data[] = new long[(int)ps.polynomialModulusExponent];
		data[0] = 100L;
		data[200] = 200L;
		data[300] = -300L;
		data[1023] = -35145234L;
		
		FVPlainText pt = new FVPlainText();
		pt.encode(pg, data);
		FVCipherText ct = pt.encrypt(pg, pubKey);
		
		FVPlainText pt2 = ct.decrypt(pg, privKey);
		long data2[] = pt2.decode(pg);

		assertEquals(pg.ptRing.modulus(data[0]),pg.ptRing.modulus(data2[0]));
		assertEquals(pg.ptRing.modulus(data[200]),pg.ptRing.modulus(data2[200]));
		assertEquals(pg.ptRing.modulus(data[300]),pg.ptRing.modulus(data2[300]));
		assertEquals(pg.ptRing.modulus(data[1023]),pg.ptRing.modulus(data2[1023]));
		
	}

	@Test
	void testEncryptedAddition() {
		
		FVParameters ps = FVParameters.FVParamsN1024S128;
		FVContext pg = new FVContext(ps);
		FVPrivateKey privKey = new FVPrivateKey(pg);
		
		FVPublicKey pubKey = new FVPublicKey(pg, privKey);
		
		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)ps.polynomialModulusExponent];
		long data2[] = new long[(int)ps.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = pg.ptRing.modulus(rand.nextLong());
			data2[i] = pg.ptRing.modulus(rand.nextLong());
		}
		
		FVPlainText pt1 = new FVPlainText();
		pt1.encode(pg, data1);
		FVCipherText ct1 = pt1.encrypt(pg, pubKey);

		FVPlainText pt2 = new FVPlainText();
		pt2.encode(pg, data2);
		FVCipherText ct2 = pt2.encrypt(pg, pubKey);
		
		FVCipherText ct3 = ct1.add(pg, ct2);

		FVPlainText res = ct3.decrypt(pg, privKey);
		long datares[] = res.decode(pg);

		for(int i = 0; i < data1.length; i++)
			assertEquals(pg.ptRing.modulus(data1[i] + data2[i]), pg.ptRing.modulus(datares[i]));
		
	}

	
}
