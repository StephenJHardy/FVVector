package com.n1analytics.fvvector;

import static cc.redberry.rings.Rings.GF;
import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

import com.n1analytics.fvvector.FVParameters.SecurityParam;

import cc.redberry.rings.poly.FiniteField;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

class FVEncoderTest {

	@Test
	void testEncodeDecode() {
		
		FVParameters params = FVParameters.FVParamsN1024S128;
		FVEncoder fve = new FVEncoder(params);
		SecureRandom rand = new SecureRandom();
		
		long data[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data.length; i++)
		{
			data[i] = params.ptRing.modulus(rand.nextLong());
		}
		
		UnivariatePolynomialZp64 encoded = fve.encode(data);
		
		long encValues[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < encValues.length; i++)
			encValues[i] = encoded.get(i);
		
		long[] decoded = fve.decode(encoded);
		
		for(int i = 0; i < data.length; i++)
		{
			assertEquals(decoded[i], encoded.ring.modulus(data[i])); // got the right value
			assertEquals(encValues[i], encoded.get(i));  // Nothing changed in the encoded data in the decoding process			
		}

		assertThrows(RuntimeException.class, () -> { fve.encode(new long[100]); });
		assertThrows(RuntimeException.class, () -> { fve.decode(params.ctPolyField.randomElement()); });
	}

	@Test
	void testEncodedArithmetic() {
		FVParameters params = FVParameters.FVParamsN1024S128;
		FVEncoder fve = new FVEncoder(params);
		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = params.ptRing.modulus(rand.nextLong());
		}
		
		long data2[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data2.length; i++)
		{
			data2[i] = params.ptRing.modulus(rand.nextLong());
		}
		
		UnivariatePolynomialZp64 encoded1 = fve.encode(data1);
		UnivariatePolynomialZp64 encoded2 = fve.encode(data2);
		
		long encValues1[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < encValues1.length; i++)
			encValues1[i] = encoded1.get(i);
		long encValues2[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < encValues2.length; i++)
			encValues2[i] = encoded2.get(i);
		
		UnivariatePolynomialZp64 res = params.ptPolyField.add(encoded1,encoded2);
		long[] decoded = fve.decode(res);

		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(decoded[i], encoded1.ring.modulus(data1[i] + data2[i])); // got the right value
			assertEquals(encValues1[i], encoded1.get(i));  // Nothing changed in the encoded data in the addition process			
			assertEquals(encValues2[i], encoded2.get(i));  // Nothing changed in the encoded data in the addition process			
		}


		UnivariatePolynomialZp64 res2 = params.ptPolyField.multiply(encoded1,encoded2);
		long[] decoded2 = fve.decode(res2);

		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(decoded2[i], encoded1.ring.modulus(data1[i] * data2[i])); // got the right value
			assertEquals(encValues1[i], encoded1.get(i));  // Nothing changed in the encoded data in the multiplication process			
			assertEquals(encValues2[i], encoded2.get(i));  // Nothing changed in the encoded data in the multiplication process			
		}
	}

	@Test
	public void testInterchangeSlots() throws Exception {
		FVParameters params = FVParameters.FVParamsN1024S128;
		FVEncoder fve = new FVEncoder(params);
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = (long)i;
		}
		UnivariatePolynomialZp64 p1 = fve.encode(data1);
		UnivariatePolynomialZp64 p2 = fve.interchangeSlots(p1);
		long[] decoded = fve.decode(p2);
		
		assertEquals(p2.size(), p1.size());
		for(int i = 0; i < data1.length/2; i++)
		{
			assertEquals(decoded[i],i + data1.length/2); // got the right value
			assertEquals(decoded[i + data1.length/2], i);  	
		}
		
		
	}
	
	@Test
	public void testRotateLeft() throws Exception {
		FVParameters params = FVParameters.FVParamsN1024S128;
		FVEncoder fve = new FVEncoder(params);
		
		long data1[] = new long[(int)params.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = (long)(i);
		}
		UnivariatePolynomialZp64 p1 = fve.encode(data1);
		UnivariatePolynomialZp64 p2 = fve.rotateLeft(p1,217);
		long[] decoded = fve.decode(p2);
		
		assertEquals(p2.size(), p1.size());
		for(int i = 0; i < data1.length/2; i++)
		{
			int i1 = Math.floorMod(i+217, data1.length/2);
//			System.out.println(" " + decoded[i] + " " + i1);
			assertEquals(decoded[i],(long)i1); // got the right value
			assertEquals(decoded[i + data1.length/2], (long)(i1 + data1.length/2));  	
		}
		
		
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
