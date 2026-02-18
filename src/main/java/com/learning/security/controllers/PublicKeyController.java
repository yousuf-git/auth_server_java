package com.learning.security.controllers;

import com.learning.security.utils.JwtUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * <h2>PublicKeyController</h2>
 * <p>
 * <b>Purpose:</b><br>
 * Provides public endpoints for external systems to retrieve the JWT public key
 * for token verification when using RS256 algorithm.<br>
 * </p>
 * <ul>
 *   <li>Exposes the RSA public key in PEM format for external system integration</li>
 *   <li>Only available when RS256 signing algorithm is configured</li>
 *   <li>Enables external systems to verify JWT tokens independently</li>
 * </ul>
 * <p><b>When is it used?</b></p>
 * <ul>
 *   <li>Called by external systems during their initial setup to retrieve the public key</li>
 *   <li>Can be periodically fetched if key rotation is implemented</li>
 * </ul>
 */
@Tag(name = "Public Key", description = "JWT Public Key API for External Systems")
@RestController
@RequestMapping("/api/public-key")
public class PublicKeyController {

    @Autowired
    private JwtUtils jwtUtils;

    @Value("${yousuf.app.jwtSigningAlgorithm:RS256}")
    private String jwtSigningAlgorithm;

    /**
     * <h3>getPublicKey</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Returns the RSA public key in PEM format for external systems to verify JWT tokens.<br>
     * </p>
     * <ul>
     *   <li>Returns the public key as plain text in PEM format</li>
     *   <li>Only works when RS256 algorithm is configured</li>
     *   <li>External systems can use this key to verify token signatures</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>During external system setup to obtain the public key</li>
     *   <li>GET request to /api/public-key</li>
     * </ul>
     * <p><b>Response Format:</b></p>
     * <pre>
     * -----BEGIN PUBLIC KEY-----
     * MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
     * -----END PUBLIC KEY-----
     * </pre>
     * 
     * @return ResponseEntity containing the public key as text/plain
     */
    @Operation(
        summary = "Get JWT Public Key",
        description = "Returns the RSA public key in PEM format for external systems to verify JWT tokens. Only available when RS256 algorithm is configured."
    )
    @GetMapping(produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> getPublicKey() {
        try {
            if (!"RS256".equals(jwtSigningAlgorithm)) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("Public key is not available. Server is using symmetric key algorithm (HS256).");
            }
            
            String publicKey = jwtUtils.getPublicKeyPem();
            return ResponseEntity.ok(publicKey);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error retrieving public key: " + e.getMessage());
        }
    }

    /**
     * <h3>getPublicKeyInfo</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Returns metadata about the JWT signing configuration including algorithm and key format.<br>
     * </p>
     * <ul>
     *   <li>Provides information about the signing algorithm in use</li>
     *   <li>Includes the public key when RS256 is configured</li>
     *   <li>Helps external systems understand the verification requirements</li>
     * </ul>
     * 
     * @return ResponseEntity containing JSON with algorithm and key info
     */
    @Operation(
        summary = "Get JWT Configuration Info",
        description = "Returns information about JWT signing configuration including algorithm and public key (for RS256)"
    )
    @GetMapping(value = "/info", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getPublicKeyInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("algorithm", jwtSigningAlgorithm);
        info.put("keyType", "RS256".equals(jwtSigningAlgorithm) ? "asymmetric" : "symmetric");
        
        if ("RS256".equals(jwtSigningAlgorithm)) {
            try {
                info.put("publicKey", jwtUtils.getPublicKeyPem());
                info.put("publicKeyFormat", "PEM");
                info.put("description", "Use the public key to verify JWT tokens signed by this server");
            } catch (IOException e) {
                info.put("error", "Error retrieving public key: " + e.getMessage());
            }
        } else {
            info.put("description", "Server is using symmetric key algorithm. Public key is not available.");
        }
        
        return ResponseEntity.ok(info);
    }
}
