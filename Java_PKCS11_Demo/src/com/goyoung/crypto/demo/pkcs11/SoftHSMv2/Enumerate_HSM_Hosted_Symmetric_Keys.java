package com.goyoung.crypto.demo.pkcs11.SoftHSMv2;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class Enumerate_HSM_Hosted_Symmetric_Keys {
	
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, InvalidKeyException, SignatureException {
		// TODO Auto-generated method stub
			
		   char [] pin = {'1', '2', '3', '4'};//HSM token PKI/password
		   KeyStore HSM_Based_JavaKeyStore = KeyStore.getInstance("PKCS11","SunPKCS11-SoftHSMv2");//crypto-provider is called: SunPKCS11-SoftHSMv2
		   HSM_Based_JavaKeyStore.load(null, pin);
		   
		   System.out.println("crypto objects contained on HSM: ");
		   //list all the certificate objects on the HSM
		   Enumeration<?> aliases = HSM_Based_JavaKeyStore.aliases();
	        while (aliases.hasMoreElements()) {
	            Object alias = aliases.nextElement();
	            try {
	                Key key0 = HSM_Based_JavaKeyStore.getKey(alias.toString(),pin);
	                System.out.println("Name: " + alias.toString() + " | Algorithm: " + key0.getAlgorithm());	

	                
	            } catch (Exception e) {
	                continue;
	            }
	        }
		
	}

}