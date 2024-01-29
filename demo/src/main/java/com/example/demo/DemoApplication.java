package com.example.demo;

import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@SpringBootApplication
public class DemoApplication {

	private static String keyId = UUID.randomUUID().toString();

	public static void main(String[] args) throws Exception {
//		/***********************************************/
//		SecretKey secretKey = AESUtils.generateAESKey();
//		String plaintext = "Hello, AES!";
//		String ciphertext = AESUtils.encrypt(plaintext, secretKey);
//		System.out.println("AES encrypted Text: " + ciphertext);
//		String decryptedText = AESUtils.decrypt(ciphertext, secretKey);
//		System.out.println("AES decrypted Text: " + decryptedText);
//
//		/***********************************************/
//		KeyPair keyPair = RSAUtils.generateRSAKey();
//		String data = "Hello, RSA!";
//		String encryptData = RSAUtils.encrypt(data, keyPair.getPublic());
//		System.out.println("RSA encrypted Text: " + encryptData);
//		String decryptedData = RSAUtils.decrypt(encryptData, keyPair.getPrivate());
//		System.out.println("RSA decrypted Text: " + decryptedData);
//
//		/***********************************************/
//
//		JWSHeader headerJWS = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("key-id").build();
//
//		String jwt = JWTUtils.signJWT(headerJWS, claimsSet, keyPair.getPrivate());
//
//		System.out.println("\nGenerated JWS: " + jwt);
//		// Verify the JWT
//		boolean isValid = JWTUtils.verifyJWT(jwt, keyPair.getPublic());
//		System.out.println("JWT is valid: " + isValid);
//
		/***********************************************/
		KeyPair keyPair = RSAUtils.generateRSAKey();
		SecretKey AesGcm128Key = AESUtils.generateAESKey("AES", 128);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();

		Map<String, Object> claims = Map.of("username", "admin", "permission", List.of("read", "write"));

		for (Map.Entry<String, Object> entry : claims.entrySet()) {
			claimsSet = new JWTClaimsSet.Builder(claimsSet)
					.claim(entry.getKey(), entry.getValue())
					.build();
		}
		claimsSet = new JWTClaimsSet.Builder(claimsSet)
				.subject("H0@n94n8")
				.issuer("example.com")
				.issueTime(new Date())
				.expirationTime(new Date(System.currentTimeMillis() + 3600000))
				.build();

		JWEHeader headerJWE = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
				.iv(new Base64URL(UUID.randomUUID().toString()))
				.contentType("JWT")
				.build();

		String jwe = JWTUtils.encryptJWE(headerJWE, claimsSet, (RSAPublicKey) keyPair.getPublic(), AesGcm128Key);
		System.out.println("\nGenerated JWE: " + jwe);

		// Decrypt and verify JWE
		JWTUtils.decryptJWE(jwe, (RSAPrivateKey) keyPair.getPrivate(), AesGcm128Key);

		// Parse JWE string
		JWEObject jweObject = JWEObject.parse(jwe);

		// Extract encrypted key, initialization vector, ciphertext, and authentication tag
		Base64URL encryptedKey = jweObject.getEncryptedKey();
//		Base64URL iv = jweObject.getHeader().getIV();
		String protectedHeader = (String) jweObject.getHeader().getCustomParam("protected");
		Base64URL cipherText = jweObject.getCipherText();
		Base64URL authTag = jweObject.getAuthTag();

		// Do something with the extracted information
		System.out.println("\nEncrypted Key: " + encryptedKey);
//		System.out.println("Initialization Vector: " + iv);
		System.out.println("Protected Header: " + protectedHeader);
		System.out.println("Cipher Text: " + cipherText);
		System.out.println("Authentication Tag: " + authTag);
	}
}
