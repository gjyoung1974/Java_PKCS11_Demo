package com.goyoung.crypto.demo.pkcs11.SoftHSMv2;

import java.io.IOException;

import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class SoftHSMv2_list_objects {
	
	public static final long  CKF_SERIAL_SESSION    = 0x00000004L;
	public static final long  CKF_RW_SESSION        = 0x00000002L;

	public static void main(String[] args) throws IOException, PKCS11Exception {
		// TODO Auto-generated method stub
		
		CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
		PKCS11 p11 = PKCS11.getInstance("/usr/local/lib/softhsm/libsofthsm2.so", "C_GetFunctionList", initArgs, false);
		long hSession = p11.C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, null, null);
		
		long[] slots = p11.C_GetSlotList(true);
		char [] pin = {'1', '2', '3', '4' };
		p11.C_Login(hSession, PKCS11Constants.CKU_USER, pin);
       
        String label = new String(p11.C_GetTokenInfo(slots[0]).label);
     
        
        System.out.println(label);

	}

}
