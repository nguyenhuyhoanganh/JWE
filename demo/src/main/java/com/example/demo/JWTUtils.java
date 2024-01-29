package com.example.demo;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

public class JWTUtils {

    public static String signJWT(JWSHeader header, JWTClaimsSet claimsSet, PrivateKey privateKey) {
        try {
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (JOSEException e) {
            e.printStackTrace();
            return null;
        }
    }
    public static boolean verifyJWT(String jwt, PublicKey publicKey) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        boolean isValid = signedJWT.verify(verifier) && new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime());

        return isValid;
    }

    public static String encryptJWE(JWEHeader header, JWTClaimsSet claimsSet, RSAPublicKey rsaPublicKey, SecretKey secretKey) {
        try {

            JWEObject jweObject = new JWEObject(header, new Payload(claimsSet.toJSONObject()));
            // sử dụng rsa
            JWEEncrypter encrypter = new RSAEncrypter(rsaPublicKey, secretKey);
            jweObject.encrypt(encrypter);

            // encrypt header, put to "protected" in new header
            String encryptProtectedHeader = AESUtils.encrypt(header.toBase64URL().toString(), secretKey);
            JWEHeader newHeader =  new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                    .customParam("protected", encryptProtectedHeader)
                    .build();
            String jwe = jweObject.serialize();

            // replace header
            return replaceHeader(newHeader.toBase64URL().toString(), jwe);
        } catch (Exception e ) {
            e.printStackTrace();
            return null;
        }
    }

    public static void decryptJWE(String jwe, RSAPrivateKey privateKey, SecretKey secretKey) throws Exception {
        JWEObject jweObject = JWEObject.parse(jwe);

        JWEHeader header = jweObject.getHeader();

        String encryptProtectedHeader = (String) header.getCustomParam("protected");
        String decryptProtectedHeader = AESUtils.decrypt(encryptProtectedHeader, secretKey);

        String originalJwe = replaceHeader(decryptProtectedHeader, jwe);

        jweObject = JWEObject.parse(originalJwe);

        jweObject.decrypt(new RSADecrypter(privateKey));

        JWTClaimsSet decryptedClaims = JWTClaimsSet.parse(jweObject.getPayload().toString());

        // Print decrypted JWT claims set
        System.out.println("\nclaims:");
        decryptedClaims.getClaims().forEach((name, value) -> {
            System.out.println(name + " : " + value);
        });
    }

    private static String replaceHeader(String header, String jwe) {
        int firstDotIndex = jwe.indexOf('.');
        jwe =  header + jwe.substring(firstDotIndex);
        return jwe;
    }

}
