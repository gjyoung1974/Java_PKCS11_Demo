package com.goyoung.crypto.demo.pkcs11.SoftHSMv2;

import java.io.IOException;
import java.util.UUID;

import org.bouncycastle.util.encoders.Hex;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class SoftHSMv2_PKCS11_Session_Demo {

	public static final long CKF_SERIAL_SESSION = 0x00000004L;// pkcs11.h constants
	public static final long CKF_RW_SESSION = 0x00000002L;

	public static void main(String[] args) throws IOException, PKCS11Exception {

		CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
		PKCS11 p11 = PKCS11.getInstance("/usr/local/lib/softhsm/libsofthsm2.so", "C_GetFunctionList", initArgs, false);//load and read the library
		long hSession = p11.C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, null, null); //PKCS11 serial, read-write session handle

		long[] slots = p11.C_GetSlotList(true);
		char[] pin = { '1', '2', '3', '4' }; //toking PIN
		p11.C_Login(hSession, PKCS11Constants.CKU_USER, pin);

		String label = new String(p11.C_GetTokenInfo(slots[0]).label);//get the first slot
		System.out.println(label);

		long modulusBits = 2048;
		byte publicExponent[] = { 1,0,1 }; // 
		//int publicExponent = 65537;
	

		String subject = "mykey";//text human readble key label
		String uuID = UUID.randomUUID().toString();//or use a UUID
		
		byte id[] = { 0x03 };//numeric key id

		CK_ATTRIBUTE[] publicKeyTemplate = { //rsa public key
				new CK_ATTRIBUTE(PKCS11Constants.CKA_ID, id),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, uuID),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, true),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_ENCRYPT, true),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_VERIFY, true),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_WRAP, true),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_MODULUS_BITS, modulusBits),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_PUBLIC_EXPONENT, publicExponent) };

		CK_ATTRIBUTE[] privateKeyTemplate = { //rsa private key
				new CK_ATTRIBUTE(PKCS11Constants.CKA_ID, id),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, uuID),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, true),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_PRIVATE, true),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_PRIVATE, true),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_DECRYPT, true),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_SIGN, true),
				new CK_ATTRIBUTE(PKCS11Constants.CKA_UNWRAP, true) };

		CK_MECHANISM mech = new CK_MECHANISM(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);//RSA PKCS11 key generation

		long[] newRSAKeyHandle = p11.C_GenerateKeyPair(hSession, mech,
				publicKeyTemplate, privateKeyTemplate);
		p11.C_GetSessionInfo(hSession).toString();

		System.out.println(newRSAKeyHandle[0] + "" + newRSAKeyHandle[1]);

		p11.C_Logout(hSession);
		p11.C_CloseSession(hSession);

	}

}
