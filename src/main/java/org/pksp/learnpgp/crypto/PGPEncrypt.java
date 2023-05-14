package org.pksp.learnpgp.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.CompressionAlgorithm;
import org.c02e.jpgpj.EncryptionAlgorithm;
import org.c02e.jpgpj.Encryptor;
import org.c02e.jpgpj.HashingAlgorithm;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Ring;
import org.c02e.jpgpj.Subkey;

public class PGPEncrypt {
	
	private String pgpPrivateKeyPath;
	private String pgpPvtKeySecret;
	private String publicKeyPath;
	
	public PGPEncrypt(String pgpPrivateKeyPath, String pgpPvtKeySecret, String publicKeyPath) {
		this.pgpPrivateKeyPath = pgpPrivateKeyPath;
		this.pgpPvtKeySecret = pgpPvtKeySecret;
		this.publicKeyPath = publicKeyPath;
	}
	
	public String encryptIt(String contentToEncrypt) {
		ByteArrayInputStream byteArrayInStream = new ByteArrayInputStream(contentToEncrypt.getBytes());
		ByteArrayOutputStream byteArrayOutStream = new ByteArrayOutputStream();
		
		Encryptor encryptor = null;
	    try {
	        // use Bob's public key for encryption
	        //encryptor = new Encryptor(new Key(new File(publicKeyPath)));
	    	List<Key> keyList = new ArrayList<>();
	    	keyList.add(new Key(new File(publicKeyPath)));

	        // manipulate Alice's secret key before supplying it to the encryptor
	        Key alice = new Key(new File(pgpPrivateKeyPath));
	        for (Subkey subkey : alice.getSubkeys()) {
	            // don't use Alice's encryption subkey
	            if (subkey.isForEncryption()) {
	                subkey.setForEncryption(false);
	            }
	            // unlock Alice's signing subkey with a passphrase of "password123"
	            if (subkey.isForSigning()) {
	                subkey.setPassphraseChars(pgpPvtKeySecret.toCharArray());
	            }
	        }

	        //List<Key> keyList = new ArrayList<>(encryptor.getRing().getKeys());
	        keyList.add(alice);
	        //keyList.add(new Key(new File(publicKeyPath)));
	        encryptor = new Encryptor(new Ring(keyList));
	    	
	        // use custom encryption, signing, and compression algorithms
	        encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.CAST5);
	        encryptor.setSigningAlgorithm(HashingAlgorithm.SHA1);
	        encryptor.setCompressionAlgorithm(CompressionAlgorithm.ZLIB);
	        // output with ascii armor
	        encryptor.setAsciiArmored(true);

	        //encryptor.getRing().getKeys().add(alice);

	        // encrypt the (ascii-armored) message to the response
	        encryptor.encrypt(byteArrayInStream, byteArrayOutStream);
	    } catch (PGPException | IOException e) {
	        e.printStackTrace();
	    } finally {
	        // zero-out passphrase and release private key material for GC
	        if (encryptor != null)
	            encryptor.clearSecrets();
	    }
	    
		// After encrypting
		String encryptedStr = new String(byteArrayOutStream.toByteArray());
		return encryptedStr;
	}
}
