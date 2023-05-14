package org.pksp.learnpgp.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Decryptor;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Ring;
import org.c02e.jpgpj.Subkey;

public class PGPDecrypt {
	
	private String pgpPublicKeyPath;
	private String privateKeyPath;
	private String privateKeySecret;
	
	public PGPDecrypt(String pgpPublicKeyPath, String privateKeyPath, String privateKeySecret) {
		this.pgpPublicKeyPath = pgpPublicKeyPath;
		this.privateKeyPath = privateKeyPath;
		this.privateKeySecret = privateKeySecret;
	}
	
	public String decryptIt(String contentToDecrypt) {
		ByteArrayInputStream byteArrayInStream = new ByteArrayInputStream(contentToDecrypt.getBytes());
		ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream();
		
		try {
			List<Key> keyList = new ArrayList<>();
	    	
	    	Key pgpPublicKey = new Key(new File(pgpPublicKeyPath));
	        for (Subkey subkey : pgpPublicKey.getSubkeys()) {
	        	subkey.setForVerification(true);
	        }
	        keyList.add(pgpPublicKey);
	        
	        Key pvtKey = new Key(new File(privateKeyPath));
	        for (Subkey subkey : pvtKey.getSubkeys()) {
	        	subkey.setForDecryption(true);
	        	subkey.setPassphrase(privateKeySecret);
	        }
	        keyList.add(pvtKey);
	    	
	    	Decryptor decryptor = new Decryptor(new Ring(keyList));
	    	
	    	decryptor.decrypt(byteArrayInStream, byteArrayOutStream);
	    	
		} catch(PGPException | IOException pgpEx) {
			pgpEx.printStackTrace();
		}
		
		// After decrypting
		String decryptedStr = new String(byteArrayOutStream.toByteArray());
		
		return decryptedStr;
	}
	
}
