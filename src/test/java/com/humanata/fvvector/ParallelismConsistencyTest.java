package com.humanata.fvvector;

import static cc.redberry.rings.Rings.GF;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.util.ArrayList;
import java.util.concurrent.ForkJoinPool;

import org.junit.jupiter.api.Test;

import cc.redberry.rings.poly.FiniteField;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

class ParallelismConsistencyTest {

	@Test
	public void testMultiplyPolyArraysDivideAndRoundParallelMatchesSequential() throws Exception {
		assumeTrue(!Boolean.getBoolean("fvvector.disableParallel"),
				"Parallel path disabled via system property");
		assumeTrue(ForkJoinPool.getCommonPoolParallelism() > 1,
				"Common ForkJoinPool parallelism too low to exercise parallel path");

		int polyorder = 16;
		long modulus1 = 10L;
		long modulus2 = 30L;
		long polys1dat[][] = {
				{23, 14, 7},
				{5, 26, 9},
				{11, 3, 17}
		};
		long polys2dat[][] = {
				{29, 1, 8},
				{24, 14, 2},
				{6, 19, 5}
		};

		ArrayList<UnivariatePolynomialZp64> polys1 = new ArrayList<UnivariatePolynomialZp64>(3);
		ArrayList<UnivariatePolynomialZp64> polys2 = new ArrayList<UnivariatePolynomialZp64>(3);
		for (int i = 0; i < 3; i++) {
			polys1.add(UnivariatePolynomialZp64.create(modulus2, polys1dat[i]));
			polys2.add(UnivariatePolynomialZp64.create(modulus2, polys2dat[i]));
		}

		FiniteField<UnivariatePolynomialZp64> field = getGaloisField(modulus2, polyorder);
		int pairCount = polys1.size() * polys2.size();
		int threshold = Integer.getInteger("fvvector.parallelPairThreshold", 4);
		assumeTrue(pairCount >= threshold, "Input too small to trigger parallel path");

		ArrayList<UnivariatePolynomialZp64> parallelRes =
				PolynomialUtils.multiplyPolyArraysDivideAndRound(
						field, polys1, polys2, modulus2 / modulus1);

		ForkJoinPool pool = new ForkJoinPool(1);
		ArrayList<UnivariatePolynomialZp64> sequentialRes;
		try {
			sequentialRes = pool.submit(() ->
					PolynomialUtils.multiplyPolyArraysDivideAndRound(
								field, polys1, polys2, modulus2 / modulus1)).get();
		} finally {
			pool.shutdown();
		}

		assertEquals(sequentialRes.size(), parallelRes.size());
		for (int i = 0; i < sequentialRes.size(); i++) {
			UnivariatePolynomialZp64 seqPoly = sequentialRes.get(i);
			UnivariatePolynomialZp64 parPoly = parallelRes.get(i);
			assertEquals(seqPoly.size(), parPoly.size());
			for (int j = 0; j < seqPoly.size(); j++) {
				assertEquals(seqPoly.get(j), parPoly.get(j),
						"Coefficient mismatch at poly " + i + ", index " + j);
			}
		}
	}

	@Test
	public void testAccumulateDotProductParallelMatchesSequential() throws Exception {
		assumeTrue(!Boolean.getBoolean("fvvector.disableParallel"),
				"Parallel path disabled via system property");
		assumeTrue(ForkJoinPool.getCommonPoolParallelism() > 1,
				"Common ForkJoinPool parallelism too low to exercise parallel path");

		int polyorder = 16;
		long modulus = 97L;
		FiniteField<UnivariatePolynomialZp64> field = getGaloisField(modulus, polyorder);

		int count = 8;
		int threshold = Integer.getInteger("fvvector.parallelDotThreshold", 8);
		assumeTrue(count >= threshold, "Input too small to trigger parallel path");

		ArrayList<UnivariatePolynomialZp64> parray1 = new ArrayList<UnivariatePolynomialZp64>(count);
		ArrayList<UnivariatePolynomialZp64> parray2 = new ArrayList<UnivariatePolynomialZp64>(count);
		for (int i = 0; i < count; i++) {
			parray1.add(UnivariatePolynomialZp64.create(modulus, new long[] {i + 1, i + 2}));
			parray2.add(UnivariatePolynomialZp64.create(modulus, new long[] {i + 3, i + 4}));
		}

		UnivariatePolynomialZp64 parallelRes =
				PolynomialUtils.accumulateDotProduct(field, field.getZero(), parray1, parray2);

		ForkJoinPool pool = new ForkJoinPool(1);
		UnivariatePolynomialZp64 sequentialRes;
		try {
			sequentialRes = pool.submit(() ->
					PolynomialUtils.accumulateDotProduct(field, field.getZero(), parray1, parray2)).get();
		} finally {
			pool.shutdown();
		}

		assertPolyEquals(sequentialRes, parallelRes);
	}

	private FiniteField<UnivariatePolynomialZp64> getGaloisField(long modulus, int polyorder)
	{
		long[] data = new long[polyorder + 1];
		data[0] = 1L;
		data[polyorder]=1L;

		return GF(UnivariatePolynomialZp64.create(modulus, data));
	}

	private void assertPolyEquals(UnivariatePolynomialZp64 expected, UnivariatePolynomialZp64 actual)
	{
		assertEquals(expected.size(), actual.size());
		for (int i = 0; i < expected.size(); i++) {
			assertEquals(expected.get(i), actual.get(i), "Coefficient mismatch at index " + i);
		}
	}
}
