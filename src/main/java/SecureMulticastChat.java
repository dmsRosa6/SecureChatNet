import EncryptionTools.CryptoException;
import EncryptionTools.CryptoStuff;
import structs.Packet;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class SecureMulticastChat extends Thread {

    // Definition of opcode for JOIN type
    public static final int JOIN = 1;
    // Definition of opcode for LEAVE type
    public static final int LEAVE = 2;
    // Definition of opcode for a regular message type (sent/received)
    public static final int MESSAGE = 3;
    // Definition of a MAGIC NUMBER (as a global identifier) for the CHAT
    public static final long CHAT_MAGIC_NUMBER = 4969756929653643804L;
    public static final short VERSION = 1;
    // Timeout for sockets
    public static final int DEFAULT_SOCKET_TIMEOUT_MILLIS = 5000;
    // Multicast socket used to send and receive multicast protocol PDUs
    protected MulticastSocket msocket;
    // Username / User-Nick-Name in Chat
    protected String username;
    // Group IP Multicast used
    protected InetAddress group;
    // Listener for Multicast events that must be processed
    protected MulticastChatEventListener listener;
    // Control  - execution thread
    protected boolean isActive;

    protected Set<String> nonce_map;

    // Multicast Chat-Messaging
    public SecureMulticastChat(String username, InetAddress group, int port, int ttl, MulticastChatEventListener listener) throws Exception {

        this.username = username;
        this.group = group;
        this.listener = listener;
        isActive = true;
        nonce_map = new HashSet<>();

        // create & configure multicast socket

        msocket = new MulticastSocket(port);
        msocket.setSoTimeout(DEFAULT_SOCKET_TIMEOUT_MILLIS);
        msocket.setTimeToLive(ttl);
        msocket.joinGroup(group);

        CryptoStuff.getInstance().registerUserKeys(username);

        // start receive thread and send multicast join message
        start();
        sendJoin();
    }

    /**
     * Sent notification when user wants to leave the Chat-messaging room
     */

    public void terminate() throws Exception {
        isActive = false;
        sendLeave();
    }

    // to process error message
    protected void error(String message) {
        System.err.println(new java.util.Date() + ": MulticastChat: "
                + message);
    }

    // Send a JOIN message
    //
    protected void sendJoin() throws Exception {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);
        Packet p = new Packet(JOIN,VERSION, CHAT_MAGIC_NUMBER, username, "");
        preparePacket(byteStream, dataStream, p);
    }

    // Process received JOIN message
    //
    protected void processJoin(String[] payloadTokens, InetAddress address, int port){
        try {
            listener.chatParticipantJoined(payloadTokens[2], address, port);
        } catch (Throwable e) {
        }
    }

    // Send LEAVE
    protected void sendLeave() throws Exception {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);
        Packet p = new Packet(LEAVE,VERSION, CHAT_MAGIC_NUMBER, username, "");
        preparePacket(byteStream, dataStream, p);
    }

    // Processes a multicast chat LEAVE and notifies listeners

    protected void processLeave(String[] payloadTokens, InetAddress address, int port){
        try {
            listener.chatParticipantLeft(payloadTokens[2], address, port);
        } catch (Throwable ignored) {
        }
    }

    // Send message to the chat-messaging room
    //
    public void sendMessage(String message) throws Exception {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        Packet p = new Packet(MESSAGE,VERSION, CHAT_MAGIC_NUMBER, username, message);
        preparePacket(byteStream, dataStream, p);

    }

    private void preparePacket(ByteArrayOutputStream byteStream, DataOutputStream dataStream, Packet p) throws IOException {
        byte[] serializedBytes = p.serialize();
        dataStream.writeInt(serializedBytes.length);
        dataStream.write(serializedBytes);

        dataStream.close();

        byte[] data = byteStream.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, group, msocket.getLocalPort());

        msocket.send(packet);
    }

    // Process a received message  //
    //
    protected void processMessage(String[] payloadTokens, InetAddress address, int port){
        try {
            listener.chatMessageReceived(payloadTokens[2], address, port, payloadTokens[3]);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    // Loop:
    // reception and demux received datagrams to process,
    // according to message types and opcodes
    //
    public void run() {
        byte[] buffer = new byte[65508];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        while (isActive) {
            try {

                // Set buffer to receive UDP packet
                packet.setLength(buffer.length);
                msocket.receive(packet);

                // Read received datagram
                DataInputStream istream =
                        new DataInputStream(new ByteArrayInputStream(packet.getData(),
                                packet.getOffset(), packet.getLength()));

                int length = istream.readInt();
                byte[] serializedBytes = new byte[length];
                istream.readFully(serializedBytes);
                Packet p = Objects.requireNonNull(Packet.deserialize(serializedBytes));

                // Only accepts CHAT-MAGIC-NUMBER of the Chat
                if (p.getMagicNumber() != CHAT_MAGIC_NUMBER)
                    continue;

                if (!checkPacketValidity(p))
                    continue;

                String[] payloadTokens = Packet.packetPayloadDecrypt(p);


                if (!nonce_map.add(payloadTokens[1]))
                    continue;

                if (!checkSignature(p.getControlHeader() + p.getChatMessagePayload(), p.getSignature(), payloadTokens[2]))
                    continue;

                switch (Integer.parseInt(payloadTokens[0])) {
                    case JOIN:
                        processJoin(payloadTokens, packet.getAddress(), packet.getPort());
                        break;
                    case LEAVE:
                        processLeave(payloadTokens,packet.getAddress(), packet.getPort());
                        break;
                    case MESSAGE:
                        processMessage(payloadTokens,packet.getAddress(), packet.getPort());
                        break;
                    default:
                        error("Error; Unknown type " + payloadTokens[0] + " sent from  "
                                + packet.getAddress() + ":" + packet.getPort());
                }

            } catch (InterruptedIOException e) {

                /**
                 * Handler for Interruptions ...
                 * WILL DO NOTHING ,,,
                 * Used for debugging / control if wanted ... to notify the loop interruption
                 */

            } catch (Throwable e) {
                error("Processing error: " + e.getClass().getName() + ": "
                        + e.getMessage());
            }
        }

        try {
            msocket.close();
        } catch (Throwable ignored) {
        }
    }

    private boolean checkPacketValidity(Packet p) throws NoSuchAlgorithmException, InvalidKeyException, CryptoException, NoSuchPaddingException {
        return p.getMacProof().equals(CryptoStuff.getInstance().generateMAC(p.getControlHeader() + p.getSignature() + p.getChatMessagePayload()));
    }

    private boolean checkSignature(String plaintext, String signature, String sender) throws Exception {
        return CryptoStuff.getInstance().verifySignature(plaintext, signature, sender);
    }
}
