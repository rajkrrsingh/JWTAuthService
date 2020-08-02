package org.example;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class JwtAuthService{

    protected SignedJWT generateJWT(String sub, Date expires, RSAPrivateKey privateKey)
            throws Exception {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(sub)
                .issueTime(new Date(new Date().getTime()))
                .issuer("https://c2id.com")
                .claim("scope", "openid")
                .audience("bar")
                .expirationTime(expires)
                .build();
        List<String> aud = new ArrayList<String>();
        aud.add("bar");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        JWSSigner signer = new RSASSASigner(privateKey);

        signedJWT.sign(signer);

        return signedJWT;
    }

    protected boolean parseAndValidateToken(String serializedJWT, RSAPublicKey publicKey) {
        SignedJWT jwtToken = null;
        boolean valid = false;
        try {
            jwtToken = SignedJWT.parse(serializedJWT);
        } catch (ParseException e) {
            e.printStackTrace();
            return false;
        }
        valid = validateToken(jwtToken,publicKey);
        return valid;
    }

    protected boolean validateToken(SignedJWT jwtToken, RSAPublicKey publicKey) {
        boolean sigValid = validateSignature(jwtToken,  publicKey);
        if (!sigValid) {
            System.out.println("signature is not valid");
        }
        boolean audValid = validateAudiences(jwtToken);
        if (!audValid) {
            System.out.println("aud didnt match");
        }
        boolean expValid = validateExpiration(jwtToken);
        if (!expValid) {
            System.out.println("Token reached expiry date");
        }

        return sigValid && audValid && expValid;
    }

    protected boolean validateSignature(SignedJWT jwtToken,RSAPublicKey publicKey) {
        boolean valid = false;
        if (JWSObject.State.SIGNED == jwtToken.getState()) {
            if (jwtToken.getSignature() != null) {
                try {
                    JWSVerifier verifier = new RSASSAVerifier(publicKey);
                    if (jwtToken.verify(verifier)) {
                        valid = true;
                        System.out.println("signature are verified");
                    }
                } catch (JOSEException je) {
                }
            }
        }
        return valid;
    }

    protected boolean validateAudiences(SignedJWT jwtToken) {
        try {
            return jwtToken.getJWTClaimsSet().getSubject().equals("raj@example.org")
            || jwtToken.getJWTClaimsSet().getAudience().contains("bar");
        } catch (ParseException e) {
            e.printStackTrace();
            return false;
        }
    }

    protected boolean validateExpiration(SignedJWT jwtToken) {
        boolean valid = false;
        try {
            Date expires = jwtToken.getJWTClaimsSet().getExpirationTime();
            if (expires == null || new Date().before(expires)) {
                valid = true;
            } else {
            }
        } catch (ParseException pe) {
        }
        return valid;
    }

}
