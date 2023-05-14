package org.pksp.learnpgp.service;

import org.pksp.learnpgp.crypto.PGPDecrypt;
import org.pksp.learnpgp.crypto.PGPEncrypt;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// BASED ON
// https://github.com/justinludwig/jpgpj

@RestController
@RequestMapping("/api/")
public class EndpointController {
	
	@Value("${pgp.public.keyFileWithPath}")
	private String pgpPublicKeyPath;
	
	@Value("${private.keyFileWithPath}")
	private String privateKeyPath;
	
	@Value("${private.keySecret}")
	private String privateKeySecret;
	
	@Value("${pgp.private.keyFileWithPath}")
	private String pgpPrivateKeyPath;
	
	@Value("${pgp.private.keySecret}")
	private String pgpPvtKeySecret;
	
	@Value("${public.keyFileWithPath}")
	private String publicKeyPath;

	@PostMapping(value="message/encrypt", produces="application/json")
	public ResponseEntity<?> encrypt(@RequestBody String contentToEncrypt) {
		PGPEncrypt pgpEncrypt = new PGPEncrypt(pgpPrivateKeyPath, pgpPvtKeySecret, publicKeyPath);
		String encryptedContentStr = pgpEncrypt.encryptIt(contentToEncrypt);
		// pgp.private.keyFileWithPath:["+pgpPrivateKeyPath+"] \npublic.keyFileWithPath:["+publicKeyPath+"]\n
		return new ResponseEntity<String>(encryptedContentStr, HttpStatus.OK);
	}
	
	@PostMapping(value="message/decrypt", produces="application/json")
	public ResponseEntity<?> decrypt(@RequestBody String contentToDecrypt) {
		PGPDecrypt pgpDecrypt = new PGPDecrypt(pgpPublicKeyPath, privateKeyPath, privateKeySecret);
		String decryptedContentStr = pgpDecrypt.decryptIt(contentToDecrypt);
		
		//"pgp.public.keyFileWithPath:["+pgpPublicKeyPath+"] \nprivate.keyFileWithPath:["+privateKeyPath+"]"
		return new ResponseEntity<String>(decryptedContentStr, HttpStatus.OK);
	}
}
