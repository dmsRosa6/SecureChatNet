package EncryptionTools;

import Utils.ConfigNotFoundException;
import Utils.ConfigReader;

import java.io.*;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;

import Utils.Utils;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * A utility class that encrypts or decrypts a file.
 **/
public class CryptoStuff {
    private static CryptoStuff instance;

    // security.conf fields
    public static final String ALGORITHM = "ALGORITHM";
    public static final String CONFIDENTIALITY = "CONFIDENTIALITY";
    public static final String CONFIDENTIALITY_KEY = "CONFIDENTIALITY-KEY";
    public static final String HASH_FOR_NICKNAMES = "HASHFORNICKNAMES";
    public static final String MAC_KEY = "MACKEY";
    public static final String MAC_ALGORITHM = "MACALGORITHM";
    public static final String IV = "IV";
    public static final String SIGNATURE = "SIGNATURE";

    // Public Keys File Fields
    public static final String USERNAME = "USERNAME";
    public static final String HASHED_USERNAME = "HASHEDUSERNAME";
    public static final String KEY = "KEY";
    public static final String SIGNATURE_ALG = "SIGNATUREALG";
    private static final String CONF_ID = "conf1";
    private static final File CONFIG_FILE = new File("security.conf");
    private static final File PUBLIC_KEYS_FILE = new File("publickeys.conf");
    private static final String PRIVATE_KEY_FILE = "privatekey_%s.conf";
    private HashMap<String, String> configValues;
    private static Mac mac;
    private static MessageDigest digest;
    private static Signature signature;
    private static String assymetricKey;

    private CryptoStuff() {

        Security.addProvider(new BouncyCastleProvider());

        try {
            // Read the config with CONF_ID from config file
            this.configValues = ConfigReader.read(CONFIG_FILE, CONF_ID);

            // Variables initialization
            SecretKeySpec mackeySpec = new SecretKeySpec(Utils.hexStringToByteArray(configValues.get(CONFIDENTIALITY_KEY)), configValues.get(MAC_KEY));
            mac = Mac.getInstance(configValues.get(MAC_ALGORITHM));
            mac.init(mackeySpec);
            digest = MessageDigest.getInstance(configValues.get(HASH_FOR_NICKNAMES));
            signature = Signature.getInstance(configValues.get(SIGNATURE));

        } catch (FileNotFoundException | ConfigNotFoundException e) {
            System.err.println("Config file not found: " + e.getMessage());
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static CryptoStuff getInstance() {
        if (instance == null) {
            instance = new CryptoStuff();
        }
        return instance;
    }

    public String encrypt(String inputString) throws CryptoException {
        byte[] keyBytes = Utils.hexStringToByteArray(configValues.get(CONFIDENTIALITY_KEY));
        byte[] encryptedBytes = doCrypto(Cipher.ENCRYPT_MODE, keyBytes, inputString.getBytes(StandardCharsets.UTF_8));
        return Utils.toHex(encryptedBytes);
    }

    public String decrypt(String inputHex) throws CryptoException {
        byte[] keyBytes = Utils.hexStringToByteArray(configValues.get(CONFIDENTIALITY_KEY));
        return new String(doCrypto(Cipher.DECRYPT_MODE, keyBytes, Utils.hexStringToByteArray(inputHex)), StandardCharsets.UTF_8);
    }

    public String hashString(String input) {
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        return Utils.toHex(hashBytes(inputBytes));
    }

    public String generateMAC(String input) throws CryptoException {
        try {
            if (mac == null) throw new CryptoException("MAC is not initialized.");

            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
            byte[] macBytes = mac.doFinal(inputBytes);

            return Utils.toHex(macBytes);

        } catch (IllegalStateException e) {
            throw new CryptoException("Error generating MAC", e);
        }
    }

    public byte[] hashBytes(byte[] inputBytes) {
        return digest.digest(inputBytes);
    }

    private byte[] doCrypto(int cipherMode, byte[] key, byte[] inputFile) throws CryptoException {
        try {
            Key secretKey = new SecretKeySpec(key, configValues.get(ALGORITHM));
            String[] tokens = configValues.get(CONFIDENTIALITY).split("/");
            Cipher cipher = Cipher.getInstance(configValues.get(CONFIDENTIALITY));
            if (tokens[0].equals("RC4"))
                cipher.init(cipherMode, secretKey);
            else {
                AlgorithmParameterSpec ivSpec;
                if (tokens[0].equals("ChaCha20"))
                    ivSpec = new ChaCha20ParameterSpec(Utils.hexStringToByteArray(configValues.get(IV)), 1);
                else if (tokens.length > 1 && tokens[1].equals("GCM"))
                    ivSpec = new GCMParameterSpec(128, configValues.get(IV).getBytes());
                else
                    ivSpec = new IvParameterSpec(configValues.get(IV).getBytes());

                cipher.init(cipherMode, secretKey, ivSpec);
            }

            return cipher.doFinal(inputFile);
        } catch (InvalidKeyException | BadPaddingException
                 | IllegalBlockSizeException
                 | InvalidAlgorithmParameterException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public void registerUserKeys(String username){
        try {
            KeyPair k = generateKeyPair();

            byte[] privateKeyBytes = k.getPrivate().getEncoded();
            byte[] publicKeyBytes = k.getPublic().getEncoded();

            ConfigReader.writeToFile(PUBLIC_KEYS_FILE,username,hashString(username), Utils.toHex(publicKeyBytes),signature.getAlgorithm());
            ConfigReader.writeToFile(new File(String.format(PRIVATE_KEY_FILE, username)),username,hashString(username), Utils.toHex(privateKeyBytes),signature.getAlgorithm());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String generateSignature(String input, String username)  {
        try {
            String privateKeyString = ConfigReader.getUserKeys(new File(String.format(PRIVATE_KEY_FILE, username)), username).get(KEY);
            byte[] privateKeyBytes = Utils.hexStringToByteArray(privateKeyString);

            // Create a PKCS8EncodedKeySpec from the decoded key bytes
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

            // Generate an RSAPrivateKey from the PKCS8EncodedKeySpec
            KeyFactory keyFactory = KeyFactory.getInstance(assymetricKey);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            // Signing
            Signature signature = Signature.getInstance(configValues.get(SIGNATURE));
            signature.initSign(privateKey);
            signature.update(Utils.toByteArray(input));

            return Utils.toString(signature.sign());

        } catch (FileNotFoundException | ConfigNotFoundException | SignatureException | NoSuchAlgorithmException |
                 InvalidKeySpecException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verifySignature(String message, String sign, String username) {
        try {
            String publicKeyString = ConfigReader.getUserKeys(PUBLIC_KEYS_FILE, username).get(KEY);
            byte[] publicKeyBytes = Utils.hexStringToByteArray(publicKeyString);

            // Create a PKCS8EncodedKeySpec from the decoded key bytes
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance(assymetricKey);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            //Signature verification
            signature.initVerify(publicKey);
            signature.update(Utils.toByteArray(message));

            return signature.verify(Utils.toByteArray(sign));

        } catch (FileNotFoundException | ConfigNotFoundException | SignatureException | NoSuchAlgorithmException |
                 InvalidKeySpecException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator;
        if(configValues.get(SIGNATURE).equals("SHA256withRSA/PSS")){
            assymetricKey = "RSA";
            keyPairGenerator = KeyPairGenerator.getInstance(assymetricKey);
            keyPairGenerator.initialize(2048);
        }
        else{
            assymetricKey = "ECDSA";
            keyPairGenerator = KeyPairGenerator.getInstance(assymetricKey);
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecSpec);
        }
        return keyPairGenerator.generateKeyPair();
    }
}