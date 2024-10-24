package structs;

import EncryptionTools.CryptoException;
import EncryptionTools.CryptoStuff;
import Utils.Utils;
import jdk.jshell.execution.Util;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Packet implements Serializable{
    private final static String DELIM = "###";

    /**
     * /   Header params
     */
    private final short version;
    private final long magicNumber;
    private final String hashUsername;

    /**
     * Message payload - E(USERNAME||MSG_TYPE||NONCE||MESSAGE)
     */
    private final String chatMessagePayload;
    private final String signature;

    /**
     * MAC-PROOF
     */
    private final String macProof;

       public Packet(int msgMode,short version, long magicNumber, String username, String chatMessage) throws Exception {

        // Header
        this.version = version;
        this.magicNumber = magicNumber;
        this.hashUsername = CryptoStuff.getInstance().hashString(username);

        // Payload
        SecureRandom rand = new SecureRandom();
        byte[] nonceBytes = new byte[16];
        rand.nextBytes(nonceBytes);
        String nonceHexString = Utils.toHex(nonceBytes);
        String input = String.join(DELIM, String.valueOf(msgMode), nonceHexString, username, chatMessage);
        chatMessagePayload = CryptoStuff.getInstance().encrypt(input);

        // Digital Signature
        signature = CryptoStuff.getInstance().generateSignature(getControlHeader() + getChatMessagePayload(), username);

        // MAC-Proof
        macProof = CryptoStuff.getInstance().generateMAC(String.valueOf(version) + magicNumber + hashUsername + signature + chatMessagePayload);
    }

    public String getControlHeader() {
        return String.valueOf(version) + magicNumber + hashUsername;
    }

    public long getMagicNumber() {
        return magicNumber;
    }

    public String getChatMessagePayload() {
        return chatMessagePayload;
    }

    public String getSignature() {
        return signature;
    }

    public String getMacProof() {
        return macProof;
    }

    @Override
    public String toString() {
        return getControlHeader() + getChatMessagePayload() + getMacProof();
    }

    public static String[] packetPayloadDecrypt(Packet packet) throws NoSuchAlgorithmException, InvalidKeyException, CryptoException, NoSuchPaddingException {
        String decryptedPayload = CryptoStuff.getInstance().decrypt(packet.getChatMessagePayload());
        return decryptedPayload.split(DELIM);
    }

    public byte[] serialize() throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeObject(this);
            return bos.toByteArray();
        }
    }

    public static Packet deserialize(byte[] serializedBytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(serializedBytes);
             ObjectInput in = new ObjectInputStream(bis)) {
            return (Packet) in.readObject();
        }
    }
}
