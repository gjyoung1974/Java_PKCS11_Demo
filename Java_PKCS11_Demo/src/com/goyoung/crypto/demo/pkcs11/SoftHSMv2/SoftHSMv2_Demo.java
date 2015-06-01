package com.goyoung.crypto.demo.pkcs11.SoftHSMv2;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.UUID;

public class SoftHSMv2_Demo {

	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, IllegalStateException, NoSuchProviderException, SignatureException {
		// TODO Auto-generated method stub

		String pkcs11config =
				"library=/usr/local/lib/softhsm/libsofthsm2.so\n"+
						"name = SoftHSMv2\n"+
						"description = SoftHSMv2Token\n"+
						"slot = 0"; //force slot 0
		
				byte[] pkcs11configBytes = pkcs11config.getBytes();
				ByteArrayInputStream configStream =
				   new ByteArrayInputStream(pkcs11configBytes);
				Provider SoftHSMv2_Provider = new sun.security.pkcs11.SunPKCS11(configStream);
				Security.addProvider(SoftHSMv2_Provider);
				   
				   char [] pin = {'1', '2', '3', '4'};//PKCS11 token password
				   KeyStore softHSMv2_KeyStore = KeyStore.getInstance("PKCS11","SunPKCS11-SoftHSMv2");//crypto-provider is called: SunPKCS11-SoftHSMv2
				   softHSMv2_KeyStore.load(null, pin);			   
			        
			        Enumeration<String> aliasesEnum = softHSMv2_KeyStore.aliases();
			        while (aliasesEnum.hasMoreElements()) {
			           String alias = (String)aliasesEnum.nextElement();
			           System.out.println("Alias: " + alias);
			           X509Certificate cert =
			           (X509Certificate) softHSMv2_KeyStore.getCertificate(alias);
			           System.out.println("Certificate: " + cert);
			           PrivateKey privateKey = (PrivateKey) softHSMv2_KeyStore.getKey(alias, null);
			           System.out.println("Private key: " + privateKey);
			        }
			        
			
		
	}

}
