package com.n1analytics.fvvector;

import static cc.redberry.rings.Rings.GF;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import com.n1analytics.fvvector.FVParameters.SecurityParam;

import cc.redberry.rings.poly.FiniteField;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

class FVEncoderTest {

	@Test
	void testEncodeDecode() {
		FVParameters params = FVParameters.FVParamsN1024S128;
		FVContext pg = new FVContext(params);
		FVEncoder fve = new FVEncoder(pg);
		
		long data[] = new long[(int)params.polynomialModulusExponent];
		data[0] = 100L;
		data[200] = 200L;
		data[300] = -300L;
		data[1023] = -35145234L;
		
		UnivariatePolynomialZp64 encoded = fve.encode(data);
		long[] decoded = fve.decode(encoded);
		
		assertEquals(decoded[0], encoded.ring.modulus(data[0]));
		assertEquals(decoded[200], encoded.ring.modulus(data[200]));
		assertEquals(decoded[300], encoded.ring.modulus(data[300]));
		assertEquals(decoded[1023], encoded.ring.modulus(data[1023]));
		
		assertThrows(RuntimeException.class, () -> { fve.encode(new long[100]); });
		
	}

	@Test
	void testEncodedAddition() {
		FVParameters params = FVParameters.FVParamsN1024S128;
		FVContext pg = new FVContext(params);
		FVEncoder fve = new FVEncoder(pg);
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		data1[0] = 100L;
		data1[200] = 200L;
		data1[300] = -300L;
		data1[1023] = -35145234L;
		
		long data2[] = new long[(int)params.polynomialModulusExponent];
		data2[0] = 101L;
		data2[200] = 201L;
		data2[300] = -301L;
		data2[1023] = -351452534L;

		for(int i = 1; i < 20; i++)
		{
			data1[i] = (long)i;
			data2[i] = (long)(i-1);
		}
		
		UnivariatePolynomialZp64 encoded1 = fve.encode(data1);
		UnivariatePolynomialZp64 encoded2 = fve.encode(data2);
		UnivariatePolynomialZp64 res = pg.ptPolyField.add(encoded1,encoded2);

		long[] decoded = fve.decode(res);
		
		assertEquals(decoded[0], encoded1.ring.modulus(data1[0]+data2[0]));
		assertEquals(decoded[200], encoded1.ring.modulus(data1[200]+data2[200]));
		assertEquals(decoded[300], encoded1.ring.modulus(data1[300]+data2[300]));
		assertEquals(decoded[1023], encoded1.ring.modulus(data1[1023]+data2[1023]));

		UnivariatePolynomialZp64 res2 = pg.ptPolyField.multiply(encoded1,encoded2);
		long[] decoded2 = fve.decode(res2);
		assertEquals(decoded2[0], encoded1.ring.modulus(data1[0]*data2[0]));
		assertEquals(decoded2[200], encoded1.ring.modulus(data1[200]*data2[200]));
		assertEquals(decoded2[300], encoded1.ring.modulus(data1[300]*data2[300]));
		assertEquals(decoded2[1023], encoded1.ring.modulus(data1[1023]*data2[1023]));
	}

	@Test
	void testEncodedMultiply() {
		FVParameters params = FVParameters.FVParamsN1024S128;
		FVContext pg = new FVContext(params);
		FVEncoder fve = new FVEncoder(pg);
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		data1[0] = 100L;
		data1[200] = 200L;
		data1[300] = -300L;
		data1[1023] = -35145234L;
		
		long data2[] = new long[(int)params.polynomialModulusExponent];
		data2[0] = 101L;
		data2[200] = 201L;
		data2[300] = -301L;
		data2[1023] = -351452534L;

		for(int i = 1; i < 20; i++)
		{
			data1[i] = (long)i;
			data2[i] = (long)(i-1);
		}
		
		UnivariatePolynomialZp64 encoded1 = fve.encode(data1);
		UnivariatePolynomialZp64 encoded2 = fve.encode(data2);
		UnivariatePolynomialZp64 res2 = pg.ptPolyField.multiply(encoded1,encoded2);
		long[] decoded2 = fve.decode(res2);

		assertEquals(decoded2[0], encoded1.ring.modulus(data1[0]*data2[0]));
		assertEquals(decoded2[200], encoded1.ring.modulus(data1[200]*data2[200]));
		assertEquals(decoded2[300], encoded1.ring.modulus(data1[300]*data2[300]));
		assertEquals(decoded2[1023], encoded1.ring.modulus(data1[1023]*data2[1023]));
	}
	
//	@Test
//	void testPart() {
//		long n = 16;
//		long t = 97;
//		long roots[] = FVPolyGenerator.CalculateRootsOfUnity(n, t);
//		UnivariatePolynomialZp64 bases[] = FVPolyGenerator.CalculateBasisFunctions(n, t, roots);
//		
//		long[] data = new long[(int)n+1];
//		data[0] = 1L;
//		data[(int)n]=1L;
//
//		UnivariatePolynomialZp64 ptQuotientPoly = UnivariatePolynomialZp64.create(t, data);
//		FiniteField<UnivariatePolynomialZp64> ptPolyField = GF(ptQuotientPoly);
//
//		long[] values = {85, 14, 12, 28, 38, 63, 2, 40, 38, 3, 12, 77, 8, 33, 15, 58};
//		long[] reses = {45, 86, 84, 68, 36, 13, 26, 67, 24, 67, 55, 70, 57, 59, 29, 30};
//		UnivariatePolynomialZp64 res = UnivariatePolynomialZp64.zero(t);
//		for(int i = 0; i < values.length; i++)
//		{
//			res = res.add(ptPolyField.multiply(bases[i],values[i]));
//		}
//		for(int i = 0; i < n; i++)
//			assertEquals(res.get(i) , res.ring.modulus(reses[i]));
//
//		long[] values2 = {37, 35, 39, 29, 85, 79, 94, 79, 87, 73, 34, 83, 82, 58, 8, 45};
//		long[] reses2 = {41, 0, 28, 80, 5, 48, 0, 29, 40, 79, 65, 55, 38, 38, 56, 61};
//		UnivariatePolynomialZp64 res2 = UnivariatePolynomialZp64.zero(t);
//		for(int i = 0; i < values.length; i++)
//		{
//			res2 = res2.add(ptPolyField.multiply(bases[i],values2[i]));
//		}
//		for(int i = 0; i < n; i++)
//			assertEquals(res2.get(i) , res.ring.modulus(reses2[i]));
//
//		
//		
//	}

	
}
