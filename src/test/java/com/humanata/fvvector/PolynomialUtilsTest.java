package com.humanata.fvvector;

import static cc.redberry.rings.Rings.GF;
import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;

import cc.redberry.rings.poly.FiniteField;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

class PolynomialUtilsTest {

	@Test
	public void testCalculateMappingOfRoots() throws Exception {
		long map[] = PolynomialUtils.CalculateMappingOfRoots(16L);
		long groundtruth[] = {1, 29, 9, 5, 17, 13, 25, 21, 31, 3, 23, 27, 15, 19, 7, 11};
		for(int i = 0; i < map.length; i++)
			assertEquals(groundtruth[i], map[i]); // Calculated independently
	}

	
	
	@Test
	public void testCalculateRootsOfUnity() throws Exception {
		long roots[] = PolynomialUtils.CalculateRootsOfUnity(16L, 97L);
		long groundtruth[] = {19, 45, 67, 77, 78, 52, 30, 20, 46, 69, 42, 63, 51, 28, 55, 34};
		for(int i = 0; i < roots.length; i++)
			assertEquals(groundtruth[i], roots[i]); // Calculated independently
	}

	@Test
	public void testCalculateBasisFunctions() throws Exception {
		long n = 16;
		long t = 97;
		long roots[] = PolynomialUtils.CalculateRootsOfUnity(n, t);
		UnivariatePolynomialZp64 bases[] = PolynomialUtils.CalculateBasisFunctions(n, t, roots);
		for(int i = 0; i < n; i++)
		{
			for(int j = 0; j < n; j++)
			{
				long val = bases[i].evaluate(roots[j]);
				if(i==j)
					assertEquals(val,1L); // bases should evaluate to a delta function
				else
					assertEquals(val,0L);
			}
		}
	}
	void AssertSmallPoly(long n, UnivariatePolynomialZp64 sp)
	{
		long mo = 0, ze = 0, po = 0;
		for(int i= 0; i < n; i++)
		{
			
			long val = 0L;
			if(i <= sp.degree())
				val = sp.get(i);  // high order coefficients might be zero
			
			if(val==sp.ring.modulus(-1L)) mo++;
			if(val==sp.ring.modulus(0L)) ze++;
			if(val==sp.ring.modulus(1L)) po++;	

			assertTrue((val == sp.ring.modulus(-1L)) || 
					(val == sp.ring.modulus(0L)) ||
					(val == sp.ring.modulus(1L))
					);
		}

		// should be roughly uniform distribution - heuristic below for how big a divergence should happen
		// based on powerlaw scaling of outlier distribution. Bound should only be violated exponentially rarely
		double boundExpectedDeviation = Math.exp(1.0 + 0.6 * Math.log((double)n));
		assertTrue(Math.abs(mo - po) < boundExpectedDeviation);
		assertTrue(Math.abs(ze - po) < boundExpectedDeviation);
		assertTrue(Math.abs(mo - ze) < boundExpectedDeviation);
	}

	long maxAbsCoeff(long t, UnivariatePolynomialZp64 sp)
	{
		long maxv = 0L;
		long t2 = t/2;
		for(int i = 0; i < sp.degree(); i++)
		{
			long v = sp.get(i);
			if(v > t2) v -= t;
			v = Math.abs(v);
			if(v > maxv)
				maxv = v;
		}
		return maxv;
	}
	
	@Test
	public void testGenerateSmallPolynomial() throws Exception {
		long n = 16;
		long t = 97;
		UnivariatePolynomialZp64 sp = PolynomialUtils.generateSmallPolynomial(n, t);
		assertEquals(sp.coefficientRingCardinality().longValue(), t);
		assertTrue(sp.degree() <= (int)n-1); // coefficients for high orders may be zero		
		AssertSmallPoly(n, sp);
	}
	


	@Test
	public void testGenerateUniformPolynomial() throws Exception {
		long n = FVParameters.FVParamsN2048S128.maxPolynomialExponent;
		long t = FVParameters.FVParamsN2048S128.coefficientModulus; // use a bigger t to make is larger than an int
		UnivariatePolynomialZp64 sp = PolynomialUtils.generateUniformPolynomial(n, t);
		assertEquals(sp.coefficientRingCardinality().longValue(), t);
		assertEquals(sp.degree(), n-1);		 // 1/97 this will fail if top coefficient is zero
		// @todo not testing for uniformity here...
	}
	
	
	
	@Test
	public void testFVPolynomialUtil() throws Exception {
		FVParameters ps = FVParameters.FVParamsN1024S128;
		long rootsOfUnity[] = PolynomialUtils.CalculateRootsOfUnity(ps.polynomialModulusExponent, ps.plainTextModulus);
		UnivariatePolynomialZp64 bases[] = PolynomialUtils.CalculateBasisFunctions(ps.polynomialModulusExponent, ps.plainTextModulus, rootsOfUnity);
		
		for(int i = 0; i < ps.polynomialModulusExponent; i++)
		{
			for(int j = 0; j < ps.polynomialModulusExponent; j++)
			{
				long val = bases[i].evaluate(rootsOfUnity[j]);
				if(i==j)
					assertEquals(val,1L); // bases should evaluate to a delta function
				else
					assertEquals(val,0L);
			}
		}
		
		UnivariatePolynomialZp64 sp = PolynomialUtils.generateSmallPolynomial(ps.polynomialModulusExponent, ps.plainTextModulus);;
		AssertSmallPoly(ps.polynomialModulusExponent, sp);
	}

	@Test
	public void testGenerateNoisePolynomial() throws Exception {
		long n = 32768L;
		long t = 101L;
		UnivariatePolynomialZp64 sp = PolynomialUtils.generateNoisePolynomial(n, t, 3.19, 9.4 * 3.19);
		assertTrue(sp.degree() < (int)n);
		int countzero = 0, countone = 0, countminusone = 0;
		for(int i = 0; i < n; i++)
		{
			long l = sp.get(i);
			if(l == sp.ring.modulus(-1L)) countminusone++;
			else if(l == sp.ring.modulus(1L)) countone++;
			else if(l == sp.ring.modulus(0L)) countzero++;
		}
		double rat = (double)countzero / (double)(countone + countminusone);
		assertTrue(rat > 0.45 && rat < 0.6); // reasonable ratio between -1 or -1 and 0
		double rat2 = Math.abs((double)(countone - countminusone))/(double)countzero;
		assertTrue(rat2 < 0.1); // not too much variation between -1 and +1
		
		assertThrows(IllegalArgumentException.class, () -> {  PolynomialUtils.generateNoisePolynomial(n, t, -3.19, 9.4 * 3.19); });
		assertThrows(IllegalArgumentException.class, () -> {  PolynomialUtils.generateNoisePolynomial(n, t, 3.19, 9.4 * 0); });

		assertTrue(maxAbsCoeff(t,sp) < 30L);
		
	}

	@Test
	public void testDecomposePolynomial() throws Exception {
		long coeffs[] = {15,19,4,2,1,30};
		UnivariatePolynomialZp64 p = UnivariatePolynomialZp64.create(31, coeffs);
		long base = 3;
		ArrayList<UnivariatePolynomialZp64> al = PolynomialUtils.decomposePolynomial(p, base);
		UnivariatePolynomialZp64 sum = p.createZero();
		long pow = 1;
		for(int i = 0; i < al.size(); i++)
		{
			UnivariatePolynomialZp64 tmp = al.get(i).clone().multiply(pow);
			sum = sum.add(tmp);
			pow *= base;
		}
		for(int i = 0; i < p.size(); i++)
		{
			assertEquals(p.get(i),sum.get(i));
		}

		// This test has been added as having a base decomposed where there
		// was not inverse in the field highlighted a bug. This checks for that 
		// regression
		long coeffs2[] = {15,19,4,2,1,30};
		UnivariatePolynomialZp64 p2 = UnivariatePolynomialZp64.create(16, coeffs2);
		long base2 = 2;
		ArrayList<UnivariatePolynomialZp64> al2 = PolynomialUtils.decomposePolynomial(p2, base2);
		UnivariatePolynomialZp64 sum2 = p2.createZero();
		long pow2 = 1;
		for(int i = 0; i < al2.size(); i++)
		{
			UnivariatePolynomialZp64 tmp = al2.get(i).clone().multiply(pow2);
			sum2 = sum2.add(tmp);
			pow2 *= base2;
		}
		for(int i = 0; i < p2.size(); i++)
		{
			assertEquals(p2.get(i),sum2.get(i));
		}

		// test against a polynomial generated in mathematica
		
		long c3[] = {29769, 131004, 160873, 89879, 133817, 14587, 90202, 36044, 20192,
						75665, 93038, 129473, 101535, 11186, 124448, 148861};
		UnivariatePolynomialZp64 tmp = UnivariatePolynomialZp64.create(177146, c3);
		ArrayList<UnivariatePolynomialZp64> al3 = PolynomialUtils.decomposePolynomial(tmp, 3);
		long res[][] = {{0, 0, 1, 2, 2, 1, 1, 2, 2, 2, 2, 2, 0, 2, 2, 1}, {2, 0, 2, 1, 1, 2, 
			  1, 2, 1, 0, 1, 2, 2, 2, 1, 0}, {1, 0, 0, 2, 0, 0, 2, 2, 2, 1, 2, 0, 1, 
				  0, 0, 1}, {1, 1, 0, 1, 0, 0, 1, 2, 0, 0, 1, 1, 1, 0, 1, 2}, {1, 0, 
				  0, 2, 2, 0, 0, 0, 0, 1, 2, 2, 2, 0, 0, 1}, {2, 2, 2, 0, 1, 0, 2, 1, 
				  2, 2, 1, 1, 0, 1, 2, 0}, {1, 2, 1, 0, 0, 2, 0, 1, 0, 1, 1, 0, 1, 0, 
				  2, 0}, {1, 2, 1, 2, 1, 0, 2, 1, 0, 1, 0, 2, 1, 2, 2, 2}, {1, 1, 0, 1, 
				  2, 2, 1, 2, 0, 2, 2, 1, 0, 1, 0, 1}, {1, 0, 2, 1, 0, 0, 1, 1, 1, 0, 
				  1, 0, 2, 0, 0, 1}, {0, 2, 2, 1, 2, 0, 1, 0, 0, 1, 1, 2, 1, 0, 2, 2}};
		for(int i = 0; i < al3.size(); i++)
		{
			for(int j = 0; j < 16; j++)
			{
				if(j > al3.get(i).size()) break;
				assertEquals(al3.get(i).get(j),res[i][j]);
			}
		}
		
	}

	public FiniteField<UnivariatePolynomialZp64> getGaloisField(long modulus, int polyorder)
	{
		long[] data = new long[polyorder + 1];
		data[0] = 1L;
		data[polyorder]=1L;

		FiniteField<UnivariatePolynomialZp64> field = 
				GF(UnivariatePolynomialZp64.create(modulus, data));
		return field;
	}
	
	@Test
	public void testDotProductWithPowers() throws Exception {
		int polyorder = 16;
		long modulus = 1627389952L;
		FiniteField<UnivariatePolynomialZp64> field = getGaloisField(modulus, polyorder);
			
		ArrayList<UnivariatePolynomialZp64> polys = 
				new ArrayList<UnivariatePolynomialZp64>(3);
		long data2[][] = {{535417598, 459739854, 393993695, 65288407, 1346239599, 1429464185, 
			  1617922892, 804881775, 1576327223, 60414693, 778580286, 188536349, 
			  1050432109, 361087802, 475650388, 50355034}, {977890589, 1149292142,
			   61060148, 1199448384, 937063050, 1616518840, 1435396478, 
			  1036227190, 1291512469, 475990730, 945694949, 1128025572, 441222545,
			   1573314755, 584431117, 315811798}, {123662957, 1335634052, 
			  1412800419, 1409469544, 869349960, 999054466, 1233748006, 516568274,
			   1351201799, 506835391, 1099267513, 99858481, 1548489501, 725554011,
			   1161686630, 138256546}};

		polys.add(UnivariatePolynomialZp64.create(modulus,data2[0]));
		polys.add(UnivariatePolynomialZp64.create(modulus,data2[1]));
		polys.add(UnivariatePolynomialZp64.create(modulus,data2[2]));
		
		
		long data3[] = {0, 0, 1, -1, 0, 0, 1, -1, 0, 1, 0, 1, 0, -1, 1, -1};
		
		UnivariatePolynomialZp64 atom = UnivariatePolynomialZp64.create(modulus,data3);
		
		UnivariatePolynomialZp64 result = 
				PolynomialUtils.dotProductWithPowers(field,polys,atom); 

		long groundTruth[] = {838860802, 1023410178, 117440505, 301989895, 1459617784, 788529158, 
				838860801, 335544317, 603979783, 1224736757, 318767113, 536870909, 
				553648127, 1207959555, 67108859, 1325400072};
		
		for(int i = 0; i < polyorder; i++)
		{
			assertEquals(result.get(i),groundTruth[i]);
			assertEquals(atom.get(i), data3[i]);
			for(int j = 0; j < 3; j++)
			{
				assertEquals(polys.get(j).get(i), data2[j][i]);
			}
		}
	}

	@Test
	public void testDividePolynomialAndRoundInField() throws Exception {
		int polyorder = 16;
		long modulus1 = 97L;
		long modulus2 = 1627389952L;
		FiniteField<UnivariatePolynomialZp64> field = getGaloisField(modulus1, polyorder);

		long polydat[] = {838860802, 1023410178, 117440505, 301989895, 1459617784, 788529158, 
				838860801, 335544317, 603979783, 1224736757, 318767113, 536870909, 
				553648127, 1207959555, 67108859, 1325400072};
		UnivariatePolynomialZp64 poly = UnivariatePolynomialZp64.create(modulus2,polydat);
		
		long scale = modulus2 / modulus1;
		
		UnivariatePolynomialZp64 res = 
				PolynomialUtils.dividePolynomialAndRoundInField(field, poly, scale);
		
		long testres[] = {50, 61, 7, 18, 87, 47, 50, 20, 36, 73, 19, 32, 33, 72, 4, 79};
		for(int i = 0; i < polyorder; i++)
		{
			assertEquals(res.get(i),testres[i]);
			assertEquals(poly.get(i),polydat[i]); // no change to input
		}
	
	}

	
	@Test
	public void testMultiplyPolyArraysDivideAndRoundSimple() throws Exception {
		int polyorder = 16;
		long polys1dat[][] = {{1,1},{2,2}};
		long polys2dat[][] = {{3,3},{4,4}};
		long modulus1 = 10L;
		long modulus2 = 30L;
		FiniteField<UnivariatePolynomialZp64> field = getGaloisField(modulus2, polyorder);
	
		ArrayList<UnivariatePolynomialZp64> polys1 = 
				new ArrayList<UnivariatePolynomialZp64>(2);
		ArrayList<UnivariatePolynomialZp64> polys2 = 
				new ArrayList<UnivariatePolynomialZp64>(2);

		polys1.add(UnivariatePolynomialZp64.create(modulus2,polys1dat[0]));
		polys1.add(UnivariatePolynomialZp64.create(modulus2,polys1dat[1]));
		polys2.add(UnivariatePolynomialZp64.create(modulus2,polys2dat[0]));
		polys2.add(UnivariatePolynomialZp64.create(modulus2,polys2dat[1]));

		ArrayList<UnivariatePolynomialZp64> res 
			= PolynomialUtils.multiplyPolyArraysDivideAndRound(
				field, polys1, polys2, modulus2/modulus1);
		
		long groundtruth[][] =// {{3, 6, 3}, {10, 20, 10}, {8, 16, 8}};
		{{1, 2, 1}, {3, 7, 3}, {3, 5, 3}};
		for(int i = 0 ; i < 3; i++)
		{
			for(int j = 0; j < 3; j++)
			{
				assertEquals(groundtruth[i][j], res.get(i).get(j));
			}
		}
			
	}

	@Test
	public void testMultiplyPolyArraysDivideAndRoundMedium() throws Exception {
		int polyorder = 16;
		long polys1dat[][] = {{23,14},{5,26}};
		long polys2dat[][] = {{29,1},{24,14}};
		long modulus1 = 10L;
		long modulus2 = 30L;
		ArrayList<UnivariatePolynomialZp64> polys1 = 
				new ArrayList<UnivariatePolynomialZp64>(2);
		ArrayList<UnivariatePolynomialZp64> polys2 = 
				new ArrayList<UnivariatePolynomialZp64>(2);

		FiniteField<UnivariatePolynomialZp64> field = getGaloisField(modulus2, polyorder);

		
		polys1.add(UnivariatePolynomialZp64.create(modulus2,polys1dat[0]));
		polys1.add(UnivariatePolynomialZp64.create(modulus2,polys1dat[1]));
		polys2.add(UnivariatePolynomialZp64.create(modulus2,polys2dat[0]));
		polys2.add(UnivariatePolynomialZp64.create(modulus2,polys2dat[1]));

		ArrayList<UnivariatePolynomialZp64> res 
			= PolynomialUtils.multiplyPolyArraysDivideAndRound(
				field, polys1, polys2, modulus2/modulus1);
		
		long groundtruth[][] = {{12, 23, 5}, {22, 22, 14}, {10, 21, 1}};
		for(int i = 0 ; i < 3; i++)
		{
			for(int j = 0; j < 3; j++)
			{
				assertEquals(groundtruth[i][j], res.get(i).get(j));
			}
		}
			
	}

	
	@Test
	public void testMultiplyPolyArraysDivideAndRound() throws Exception {

		long polys1dat[][] = {{1458432931, 1173437195, 179479392, 1056868531, 1459955958, 
			  632124503, 686379211, 163624770, 99410419, 1256173979, 1565436048, 
			  632367175, 351676046, 1583909151, 752380704, 
			  660124871}, {1290867504, 877530377, 85644481, 867464252, 130614303, 
			  429903933, 445646493, 281336431, 930357665, 158842477, 110632145, 
			  635324217, 639104967, 354448992, 1483801975, 1011307136}};
		long polys2dat[][] = {{1096630608, 1049230258, 679069701, 605434728, 1429414625, 255830449,
			   848989006, 936724135, 843453415, 1079292505, 26291644, 1271341684, 
			   634065915, 3611514, 812261168, 765873246}, {887744298, 91250766, 
			   1599260473, 1262457923, 394728916, 636323979, 363021822, 1101912263,
			    911238960, 200773403, 1312070313, 1228149821, 135041727, 811667641,
			    658707073, 1148465211}};
		long modulus1 = 97L;
		long modulus2 = 1627389952L;
	
		ArrayList<UnivariatePolynomialZp64> polys1 = 
				new ArrayList<UnivariatePolynomialZp64>(2);
		ArrayList<UnivariatePolynomialZp64> polys2 = 
				new ArrayList<UnivariatePolynomialZp64>(2);

		polys1.add(UnivariatePolynomialZp64.create(modulus2,polys1dat[0]));
		polys1.add(UnivariatePolynomialZp64.create(modulus2,polys1dat[1]));
		polys2.add(UnivariatePolynomialZp64.create(modulus2,polys2dat[0]));
		polys2.add(UnivariatePolynomialZp64.create(modulus2,polys2dat[1]));

		int polyorder = 16;
		FiniteField<UnivariatePolynomialZp64> field = getGaloisField(modulus2, polyorder);

		
		ArrayList<UnivariatePolynomialZp64> res 
			= PolynomialUtils.multiplyPolyArraysDivideAndRound(
				field, polys1, polys2, modulus2/modulus1);
		
		long groundtruth[][] = {{535417598, 459739854, 393993695, 65288407, 1346239599, 1429464185, 
			  1617922892, 804881775, 1576327223, 60414693, 778580286, 188536349, 
			  1050432109, 361087802, 475650388, 50355034}, {977890589, 1149292142,
			   61060148, 1199448384, 937063050, 1616518840, 1435396478, 
			  1036227190, 1291512469, 475990730, 945694949, 1128025572, 441222545,
			   1573314755, 584431117, 315811798}, {123662957, 1335634052, 
			  1412800419, 1409469544, 869349960, 999054466, 1233748006, 516568274,
			   1351201799, 506835391, 1099267513, 99858481, 1548489501, 725554011,
			   1161686630, 138256546}};
	
		for(int i = 0 ; i < 3; i++)
		{
			for(int j = 0; j < 16; j++)
			{
				assertEquals(groundtruth[i][j], res.get(i).get(j));
			}
		}
	
	
	}

	@Test
	public void testCoeffTransform() throws Exception {
		
		long data[] = {91, 15, 11, 21, 93, 10, 72, 14, 62, 39, 48, 74, 9, 26, 32, 17};
		UnivariatePolynomialZp64 poly = UnivariatePolynomialZp64.create(97, data);
		UnivariatePolynomialZp64 poly2 = PolynomialUtils.coeffTransform(poly, 7, 16);
		long groundTruth[] = {91, 83, 32, 10, 88, 76, 48, 15, 35, 17, 72, 71, 4, 74, 11, 58};
		
		for(int i = 0; i < data.length; i++)
		{
			assertEquals(poly2.get(i),groundTruth[i]);
		}
	}



	@Test
	public void testAccumulateDotProduct() throws Exception {
		long polysdat[][] = {{1458432931, 1173437195, 179479392, 1056868531, 1459955958, 
			  632124503, 686379211, 163624770, 99410419, 1256173979, 1565436048, 
			  632367175, 351676046, 1583909151, 752380704, 
			  660124871}, {1290867504, 877530377, 85644481, 867464252, 130614303, 
			  429903933, 445646493, 281336431, 930357665, 158842477, 110632145, 
			  635324217, 639104967, 354448992, 1483801975, 1011307136}};
		long polydat[] = {1096630608, 1049230258, 679069701, 605434728, 1429414625, 255830449,
			   848989006, 936724135, 843453415, 1079292505, 26291644, 1271341684, 
			   634065915, 3611514, 812261168, 765873246};
		long modulus1 = 97L;
		long modulus2 = 1627389952L;
		ArrayList<UnivariatePolynomialZp64> polys = 
				new ArrayList<UnivariatePolynomialZp64>(2);

		polys.add(UnivariatePolynomialZp64.create(modulus2,polysdat[0]));
		polys.add(UnivariatePolynomialZp64.create(modulus2,polysdat[1]));
		UnivariatePolynomialZp64 poly = UnivariatePolynomialZp64.create(modulus2,polydat);

		int polyorder = 16;
		FiniteField<UnivariatePolynomialZp64> field = getGaloisField(modulus2, polyorder);

		
		ArrayList<UnivariatePolynomialZp64> res 
			= PolynomialUtils.multiplyPolyArrayByPoly(field, polys, poly);
		
		long groundtruth[][] = {{96569399, 207421375, 1099723857, 580855771, 1231527901, 287131691, 
			  709211475, 411717495, 179218409, 1448591250, 1440568259, 1125569260,
			   1618670752, 1082203000, 392647691, 101014297}, {576884299, 
			  1131112957, 982631389, 886213686, 856609482, 1619583804, 884752103, 
			  676508744, 208414254, 1436701871, 284933876, 735200487, 520872757, 
			  1234055189, 1288104153, 351471617}};
	
		for(int i = 0 ; i < 2; i++)
		{
			for(int j = 0; j < polyorder; j++)
			{
				assertEquals(groundtruth[i][j], res.get(i).get(j));
			}
		}
		
	
	
	}
}
