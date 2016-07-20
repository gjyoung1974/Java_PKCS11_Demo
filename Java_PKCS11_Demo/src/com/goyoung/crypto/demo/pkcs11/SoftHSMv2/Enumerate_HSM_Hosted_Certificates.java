package com.goyoung.crypto.demo.pkcs11.SoftHSMv2;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class Enumerate_HSM_Hosted_Certificates {
	
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, InvalidKeyException, SignatureException {
		// TODO Auto-generated method stub
		
		   char [] pin = {'1', '2', '3', '4'};//HSM token PKI/password
		   KeyStore HSM_Based_JavaKeyStore = KeyStore.getInstance("PKCS11","SunPKCS11-SoftHSMv2");//crypto-provider is called: SunPKCS11-SoftHSMv2
		   HSM_Based_JavaKeyStore.load(null, pin);
		   
		   //list all the certificate objects on the HSM
		   Enumeration<?> aliases = HSM_Based_JavaKeyStore.aliases();
	        while (aliases.hasMoreElements()) {
	            Object alias = aliases.nextElement();
	            try {
	                X509Certificate cert0 = (X509Certificate) HSM_Based_JavaKeyStore.getCertificate(alias.toString());
	                System.out.println("Cert Serial Number: " + cert0.getSerialNumber());
	                //System.out.println("Cert Issuer: " + cert0.getIssuerDN().getName());
	                System.out.println("Cert subject: " + cert0.getSubjectDN().getName());
	                
	            } catch (Exception e) {
	                continue;
	            }
	        }
		
	}

}