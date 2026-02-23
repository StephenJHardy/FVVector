package com.humanata.fvvector;

import java.security.SecureRandom;
import java.util.ArrayList;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

/**
 * Lightweight microbenchmark for identifying hotspots worth parallelizing.
 * Uses simple nanoTime timing with warmup loops (not a substitute for JMH).
 */
public final class FVMicroBenchmark {

	private static volatile long blackhole;

	private static final class Config {
		long n = 2048L;
		boolean insecure = false;
		int warmup = 3;
		int itersSmall = 200;
		int itersMedium = 50;
		int itersLarge = 10;
		int itersKeygen = 2;

		static Config parse(String[] args) {
			Config cfg = new Config();
			for (String arg : args) {
				if (arg.startsWith("--n=")) {
					cfg.n = Long.parseLong(arg.substring("--n=".length()));
				} else if (arg.equals("--insecure")) {
					cfg.insecure = true;
				} else if (arg.startsWith("--warmup=")) {
					cfg.warmup = Integer.parseInt(arg.substring("--warmup=".length()));
				} else if (arg.startsWith("--small=")) {
					cfg.itersSmall = Integer.parseInt(arg.substring("--small=".length()));
				} else if (arg.startsWith("--medium=")) {
					cfg.itersMedium = Integer.parseInt(arg.substring("--medium=".length()));
				} else if (arg.startsWith("--large=")) {
					cfg.itersLarge = Integer.parseInt(arg.substring("--large=".length()));
				} else if (arg.startsWith("--keygen=")) {
					cfg.itersKeygen = Integer.parseInt(arg.substring("--keygen=".length()));
				}
			}
			return cfg;
		}
	}

	private static void consume(Object obj) {
		if (obj != null) {
			blackhole ^= obj.hashCode();
		}
	}

	private static void consumeLong(long value) {
		blackhole ^= value;
	}

	private static void run(String name, int warmup, int iters, Runnable op) {
		for (int i = 0; i < warmup; i++) {
			op.run();
		}
		long start = System.nanoTime();
		for (int i = 0; i < iters; i++) {
			op.run();
		}
		long end = System.nanoTime();
		double totalMs = (end - start) / 1_000_000.0;
		double perMs = totalMs / iters;
		System.out.println(String.format("%-45s %8.3f ms/op (total %.1f ms)", name + ":", perMs, totalMs));
	}

	private static FVParameters selectParams(Config cfg) {
		if (cfg.n == 1024L) {
			return cfg.insecure ? FVParameters.FVParamsN1024S128insecure : FVParameters.FVParamsN1024S128;
		}
		if (cfg.n == 2048L) {
			return cfg.insecure ? FVParameters.FVParamsN2048S128insecure : FVParameters.FVParamsN2048S128;
		}
		throw new IllegalArgumentException("Unsupported n: " + cfg.n + " (use 1024 or 2048)");
	}

	public static void main(String[] args) {
		Config cfg = Config.parse(args);
		FVParameters ps = selectParams(cfg);

		System.out.println("FVVector microbenchmark");
		System.out.println("n=" + ps.polynomialModulusExponent + ", insecure=" + cfg.insecure
				+ ", warmup=" + cfg.warmup + ", small=" + cfg.itersSmall
				+ ", medium=" + cfg.itersMedium + ", large=" + cfg.itersLarge
				+ ", keygen=" + cfg.itersKeygen);
		System.out.println();

		SecureRandom rand = new SecureRandom();
		long[] data1 = new long[(int) ps.polynomialModulusExponent];
		long[] data2 = new long[(int) ps.polynomialModulusExponent];
		for (int i = 0; i < data1.length; i++) {
			data1[i] = ps.ptRing.modulus(rand.nextLong());
			data2[i] = ps.ptRing.modulus(rand.nextLong());
		}

		FVPrivateKey privKey = new FVPrivateKey(ps);
		FVPublicKey pubKey = new FVPublicKey(privKey);
		FVEncoder encoder = new FVEncoder(ps);
		FVRelinearisationKey relinKey = new FVRelinearisationKey(privKey);
		FVContext context = new FVContext(pubKey, encoder, relinKey, null);

		UnivariatePolynomialZp64 ptEncoded = encoder.encode(data1);
		UnivariatePolynomialZp64 ctPoly = ps.generateNoiseCTPolynomial();
		long scale = ps.coefficientModulus / ps.plainTextModulus;

		ArrayList<UnivariatePolynomialZp64> ctArray1 = new ArrayList<UnivariatePolynomialZp64>(2);
		ArrayList<UnivariatePolynomialZp64> ctArray2 = new ArrayList<UnivariatePolynomialZp64>(2);
		ctArray1.add(ps.generateNoiseCTPolynomial());
		ctArray1.add(ps.generateNoiseCTPolynomial());
		ctArray2.add(ps.generateNoiseCTPolynomial());
		ctArray2.add(ps.generateNoiseCTPolynomial());

		int elementsPerKey = (int) ps.l + 1;
		ArrayList<UnivariatePolynomialZp64> decomp1 = new ArrayList<UnivariatePolynomialZp64>(elementsPerKey);
		ArrayList<UnivariatePolynomialZp64> decomp2 = new ArrayList<UnivariatePolynomialZp64>(elementsPerKey);
		for (int i = 0; i < elementsPerKey; i++) {
			decomp1.add(ps.generateNoiseCTPolynomial());
			decomp2.add(ps.generateNoiseCTPolynomial());
		}

		FVCipherText ct1 = context.encodeAndEncrypt(data1);
		FVCipherText ct2 = context.encodeAndEncrypt(data2);

		run("PolynomialUtils.multiplyPolyArraysDivideAndRound", cfg.warmup, cfg.itersLarge, () -> {
			ArrayList<UnivariatePolynomialZp64> res = PolynomialUtils.multiplyPolyArraysDivideAndRound(
					ps.ctPolyField, ctArray1, ctArray2, scale);
			consume(res);
		});

		run("PolynomialUtils.multiplyPolyArrayByPoly", cfg.warmup, cfg.itersMedium, () -> {
			ArrayList<UnivariatePolynomialZp64> res = PolynomialUtils.multiplyPolyArrayByPoly(
					ps.ctPolyField, ctArray1, ctPoly);
			consume(res);
		});

		run("PolynomialUtils.accumulateDotProduct", cfg.warmup, cfg.itersMedium, () -> {
			UnivariatePolynomialZp64 res = PolynomialUtils.accumulateDotProduct(
					ps.ctPolyField, ps.ctPolyField.getZero(), decomp1, decomp2);
			consume(res);
		});

		run("PolynomialUtils.coeffTransform", cfg.warmup, cfg.itersSmall, () -> {
			UnivariatePolynomialZp64 res = PolynomialUtils.coeffTransform(
					ctPoly, encoder.generatorPowers[1], ps.polynomialModulusExponent);
			consume(res);
		});

		run("FVEncoder.encode", cfg.warmup, cfg.itersSmall, () -> {
			UnivariatePolynomialZp64 res = encoder.encode(data1);
			consume(res);
		});

		run("FVEncoder.decode", cfg.warmup, cfg.itersSmall, () -> {
			long[] res = encoder.decode(ptEncoded);
			consumeLong(res[0]);
		});

		run("FVCipherText.multiplyWithoutRelinearisation", cfg.warmup, cfg.itersLarge, () -> {
			FVCipherText tmp = context.multiplyWithoutRelinearisation(ct1, ct2);
			consume(tmp);
		});

		run("FVRelinearisationKey constructor", 1, cfg.itersKeygen, () -> {
			FVRelinearisationKey tmp = new FVRelinearisationKey(privKey);
			consume(tmp);
		});

		run("FVRotationKey constructor", 1, cfg.itersKeygen, () -> {
			FVRotationKey tmp = new FVRotationKey(privKey, encoder);
			consume(tmp);
		});

		System.out.println();
		System.out.println("blackhole=" + blackhole);
	}
}
