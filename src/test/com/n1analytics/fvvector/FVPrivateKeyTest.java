package com.n1analytics.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class FVPrivateKeyTest {

	@Test
	void testFVPrivateKey() {
		FVContext pgen = new FVContext(FVParameters.FVParamsN1024S128);
		FVPrivateKey pk = new FVPrivateKey(pgen);
	}

}
