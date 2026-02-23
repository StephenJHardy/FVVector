package com.humanata.fvvector;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

final class FVSerialization {

	static final int VERSION = 1;

	private FVSerialization() {
	}

	static void writeParameters(FVParameters params, DataOutput out) throws IOException {
		out.writeInt(VERSION);
		out.writeUTF(params.getSecurityParam().name());
		out.writeLong(params.polynomialModulusExponent);
		out.writeLong(params.coefficientModulus);
		out.writeLong(params.plainTextModulus);
		out.writeDouble(params.noiseStandardDeviation);
		out.writeLong(params.decompositionBase);
	}

	static FVParameters readParameters(DataInput in) throws IOException {
		int version = in.readInt();
		if (version != VERSION) {
			throw new IOException("Unsupported FVParameters version: " + version);
		}
		FVParameters.SecurityParam securityParam = FVParameters.SecurityParam.valueOf(in.readUTF());
		long n = in.readLong();
		long q = in.readLong();
		long t = in.readLong();
		double sigma = in.readDouble();
		long base = in.readLong();
		return new FVParameters(securityParam, n, q, t, sigma, base);
	}

	static void writePolynomial(UnivariatePolynomialZp64 poly, DataOutput out) throws IOException {
		out.writeLong(poly.ring.modulus);
		int size = poly.size();
		out.writeInt(size);
		for (int i = 0; i < size; i++) {
			out.writeLong(poly.get(i));
		}
	}

	static UnivariatePolynomialZp64 readPolynomial(DataInput in) throws IOException {
		long modulus = in.readLong();
		int size = in.readInt();
		if (size < 0) {
			throw new IOException("Invalid polynomial size: " + size);
		}
		long[] coeffs = new long[size];
		for (int i = 0; i < size; i++) {
			coeffs[i] = in.readLong();
		}
		return UnivariatePolynomialZp64.create(modulus, coeffs);
	}

	static UnivariatePolynomialZp64 readPolynomial(DataInput in, long expectedModulus) throws IOException {
		UnivariatePolynomialZp64 poly = readPolynomial(in);
		if (poly.ring.modulus != expectedModulus) {
			throw new IOException("Polynomial modulus does not match expected modulus");
		}
		return poly;
	}

	static void writePolynomialList(List<UnivariatePolynomialZp64> polys, DataOutput out) throws IOException {
		out.writeInt(polys.size());
		for (UnivariatePolynomialZp64 poly : polys) {
			writePolynomial(poly, out);
		}
	}

	static ArrayList<UnivariatePolynomialZp64> readPolynomialList(DataInput in, long expectedModulus)
			throws IOException {
		int size = in.readInt();
		if (size < 0) {
			throw new IOException("Invalid polynomial list size: " + size);
		}
		ArrayList<UnivariatePolynomialZp64> polys = new ArrayList<UnivariatePolynomialZp64>(size);
		for (int i = 0; i < size; i++) {
			polys.add(readPolynomial(in, expectedModulus));
		}
		return polys;
	}

	static void writePolynomial2dList(List<? extends List<UnivariatePolynomialZp64>> polys, DataOutput out)
			throws IOException {
		out.writeInt(polys.size());
		for (List<UnivariatePolynomialZp64> inner : polys) {
			writePolynomialList(inner, out);
		}
	}

	static ArrayList<ArrayList<UnivariatePolynomialZp64>> readPolynomial2dList(DataInput in, long expectedModulus)
			throws IOException {
		int outer = in.readInt();
		if (outer < 0) {
			throw new IOException("Invalid polynomial list size: " + outer);
		}
		ArrayList<ArrayList<UnivariatePolynomialZp64>> polys =
				new ArrayList<ArrayList<UnivariatePolynomialZp64>>(outer);
		for (int i = 0; i < outer; i++) {
			polys.add(readPolynomialList(in, expectedModulus));
		}
		return polys;
	}
}
