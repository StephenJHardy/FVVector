package com.n1analytics.fvvector;

import java.security.SecureRandom;

public class FVBenchmark {

	
	static void timeVectorLength(long n, int ptBits, int ctBits)
	{
		FVParameters ps = FVParameters.generateParameterSet(FVParameters.SecurityParam.BITS_128, n, ptBits, ctBits-ptBits);
		FVPrivateKey privKey = new FVPrivateKey(ps);		
		FVPublicKey pubKey = new FVPublicKey(privKey);
		FVEncoder encoder = new FVEncoder(ps);
		FVRelinearisationKey relinKey = new FVRelinearisationKey(privKey);
		FVContext context = new FVContext(pubKey, encoder, relinKey); 

		SecureRandom rand = new SecureRandom();
		
		System.out.println("Vector Length: " + n);
		System.out.println("------------------------------");
		long data1[] = new long[(int)ps.polynomialModulusExponent];
		long data2[] = new long[(int)ps.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = ps.ptRing.modulus(rand.nextLong());
			data2[i] = ps.ptRing.modulus(rand.nextLong());
		}

		int nRep = 10;

		// Encode
		long startTime = System.nanoTime();
		
		for(int i = 0; i < nRep; i++)
		{
			FVPlainText pt1 = context.encode(data1);
		}
		
		long endTime = System.nanoTime();
		double duration = ((double)endTime - (double)startTime)/nRep/1000000.0;
		double ops = n * 1000.0 / duration ;
		System.out.println("Encode: " + duration + " ms (" +  ops + " ops/s)");

		// Encryption
		FVPlainText pt1 = context.encode(data1);
		startTime = System.nanoTime();
		
		for(int i = 0; i < nRep; i++)
		{
			FVCipherText ct1 = context.encrypt(pt1);
		}
		
		endTime = System.nanoTime();
		duration = ((double)endTime - (double)startTime)/nRep/1000000.0;
		
		ops = n * 1000.0 / duration ;
		System.out.println("Encryption: " + duration  + " ms (" +  ops + " ops/s)");
		
		// Encode  + Encryption
		startTime = System.nanoTime();
		
		for(int i = 0; i < nRep; i++)
		{
			pt1 = context.encode(data1);
			FVCipherText ct1 = context.encrypt(pt1);
		}
		
		endTime = System.nanoTime();
		duration = ((double)endTime - (double)startTime)/nRep/1000000.0;
		
		ops = n * 1000.0 / duration ;
		System.out.println("Encode and Encryption: " + duration  + " ms (" +  ops + " ops/s)");

		// Decryption
		FVCipherText ct1 = context.encrypt(data1);

		startTime = System.nanoTime();
		for(int i = 0; i < nRep; i++)
		{
			FVPlainText ptt = context.decrypt(ct1, privKey);
		}
		
		endTime = System.nanoTime();
		duration = ((double)endTime - (double)startTime)/nRep/1000000.0;
		
		ops = n * 1000.0 / duration ;
		System.out.println("Decryption: " + duration  + " ms (" +  ops + " ops/s)");

		// Decode
		FVCipherText ct2 = context.encrypt(data1);
		FVPlainText pt2 = context.decrypt(ct2, privKey);
		
		startTime = System.nanoTime();
		for(int i = 0; i < nRep; i++)
		{
			long data[] = context.decode(pt2);
		}
		
		endTime = System.nanoTime();
		duration = ((double)endTime - (double)startTime)/nRep/1000000.0;
		
		ops = n * 1000.0 / duration  ;
		System.out.println("Decode: " + duration  + " ms (" +  ops + " ops/s)");

		// Decode and Decryption
		ct1 = context.encrypt(data1);

		startTime = System.nanoTime();
		for(int i = 0; i < nRep; i++)
		{
			FVPlainText ptt = context.decrypt(ct1, privKey);
			long data[] = context.decode(ptt);
		}
		
		endTime = System.nanoTime();
		duration = ((double)endTime - (double)startTime)/nRep/1000000.0;
		
		ops = n * 1000.0 / duration ;
		System.out.println("Decryption: " + duration  + " ms (" +  ops + " ops/s)");

		// Addition
		ct1 = context.encrypt(data1);
		ct2 = context.encrypt(data2);
		
		startTime = System.nanoTime();
		for(int i = 0; i < nRep; i++)
		{
			FVCipherText ct3 = context.add(ct1, ct2);
		}
		
		endTime = System.nanoTime();
		duration = ((double)endTime - (double)startTime)/nRep/1000000.0;
		
		ops = n * 1000.0 / duration ;
		System.out.println("Addition encrypted: " + duration  + " ms (" +  ops + " ops/s)");

		// Relinearised multiplication
		ct1 = context.encrypt(data1);
		ct2 = context.encrypt(data2);
		
		startTime = System.nanoTime();
		for(int i = 0; i < nRep; i++)
		{
			FVCipherText ct3 = context.multiplyAndRelinearise(ct1, ct2);
		}
		
		endTime = System.nanoTime();
		duration = ((double)endTime - (double)startTime)/nRep/1000000.0;
		
		ops = n * 1000.0 / duration ;
		System.out.println("Relinearised multiplication encrypted: " + duration  + " ms (" +  ops + " ops/s)");

		// Multiplication
		ct1 = context.encrypt(data1);
		ct2 = context.encrypt(data2);
		
		startTime = System.nanoTime();
		for(int i = 0; i < nRep; i++)
		{
			FVCipherText ct3 = context.multiply(ct1, ct2);
		}
		
		endTime = System.nanoTime();
		duration = ((double)endTime - (double)startTime)/nRep/1000000.0;
		
		ops = n * 1000.0 / duration ;
		System.out.println("Multiplication encrypted: " + duration  + " ms (" +  ops + " ops/s)");

		
		// Addition unencrypted
		ct1 = context.encrypt(data1);
		
		startTime = System.nanoTime();
		for(int i = 0; i < nRep; i++)
		{
			ct2 = context.encrypt(data2);
			FVCipherText ct3 = context.add(ct1, ct2);
		}
		
		endTime = System.nanoTime();
		duration = ((double)endTime - (double)startTime)/nRep/1000000.0;
		
		ops = n * 1000.0 / duration ;
		System.out.println("Addition unencrypted: " + duration  + " ms (" +  ops + " ops/s)");

		// Multiplication unencrypted
		ct1 = context.encrypt(data1);
		
		startTime = System.nanoTime();
		for(int i = 0; i < nRep; i++)
		{
			ct2 = context.encrypt(data2);
			FVCipherText ct3 = context.multiply(ct1, ct2);
		}
		
		endTime = System.nanoTime();
		duration = ((double)endTime - (double)startTime)/nRep/1000000.0;
		
		ops = n * 1000.0 / duration ;
		System.out.println("Multiplication unencrypted: " + duration  + " ms (" +  ops + " ops/s)");
		}
	
	public static void main(String[] args)
	{
		timeVectorLength(2048, 14, 56);
		timeVectorLength(4096, 16, 60);
	}
}
