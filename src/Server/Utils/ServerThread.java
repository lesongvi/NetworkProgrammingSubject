/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Server.Utils;

import CommonModels.TextPack;
import Server.Utils.Helper;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;
import java.util.logging.*;
import java.util.regex.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 *
 * @author Nhóm 9
 */
public class ServerThread extends Thread {
    private ServerSocket serverSocket;
    private DatagramSocket clientSocket;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey, publicKeyofClient;
    private KeyPair keyPair;
    private KeyPairGenerator keyPairGenerator;
    private int stepCounter = 0;
    private String message = null;
    private final Helper helper = new Helper();
    private final int keysize = 2048;
    private SecretKey clientAESKey;
   
    public ServerThread(int port) throws IOException {
        this(new DatagramSocket(port));
   }
   
    public ServerThread(DatagramSocket sServer) throws IOException {
        clientSocket = sServer;
        new Thread(this).start();
   }
   
    @Override
    public void run() {
        DatagramPacket packet;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(getName()).log(Level.SEVERE, null, ex);
        }

        keyPairGenerator.initialize(keysize);
        keyPair = keyPairGenerator.generateKeyPair();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();
        
        try {
            // Client
            InetAddress host = null;
            int port = 7778;

            while (true) {
                switch (stepCounter) {
                    case 0:
                        // Nhận khóa RSA công khai của Client

                        System.out.println("Bước: " + stepCounter);

                        packet = receive();
                        host = packet.getAddress();
                        port = packet.getPort();
                        message = new String(packet.getData()).trim();
                        
                        System.out.println(message);
                        
                        if (message == null) return;

                        Matcher m = helper.InfoExtract(message);

                        if(!m.find()) {
                            System.err.println("Dữ liệu không hợp lệ!");
                            return;
                        }

                        String ClientModulus = m.group(1).trim();
                        String ClientPublicExponent = m.group(2).trim();

                        BigInteger bigInteger = new BigInteger(ClientModulus);
                        BigInteger bigInteger1 = new BigInteger(ClientPublicExponent);

                        RSAPublicKeySpec keyspec = new RSAPublicKeySpec(bigInteger, bigInteger1);
                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        publicKeyofClient = (RSAPublicKey) kf.generatePublic(keyspec);

                        ++stepCounter;
                        break;
                    case 1:
                        // Gửi khóa công khai RSA của máy chủ đến Client
                        System.out.println("Bước: " + stepCounter);
                        
                        send(String.valueOf(publicKey), host, port);

                        ++stepCounter;
                        break;
                    case 2:
                        // Nhận khóa AES từ Client
                        System.out.println("Bước: " + stepCounter);

                        System.out.println("Chờ dữ liệu");
                        
                        packet = receive();
                        host = packet.getAddress();
                        port = packet.getPort();
                        byte[] EncryptedClientAES = packet.getData();
                        
                        EncryptedClientAES = Arrays.copyOf(EncryptedClientAES, 256);
                        System.out.println(EncryptedClientAES.length);

                        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
                        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
                        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
                        byte[] decryptedAESKeyOfClient = cipher.doFinal(EncryptedClientAES);

                        clientAESKey = (SecretKey) new SecretKeySpec(decryptedAESKeyOfClient, 0, decryptedAESKeyOfClient.length, "AES");

                        ++stepCounter;
                        break;
                    case 3:
                        // Xử lý nội dung
                        System.out.println("Bước: " + stepCounter);
                        
                        // ping!
                        send ("ping", host, port);
                        
                        packet = receive();
                        host = packet.getAddress();
                        port = packet.getPort();
                        message = new String (packet.getData()).trim();

                        if (message.trim().length() == 0) {
                            System.err.println("Dữ liệu không hợp lệ");
                            return;
                        }
                        
                        TextPack txtPack = new TextPack(this.helper.charCount(this.decrypt(message)));
//                        txtPack
                                
                        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
                            ObjectOutputStream out = new ObjectOutputStream(bos)) {
                            out.writeObject(txtPack);
                            out.flush();
                            byte[] yourBytes = bos.toByteArray();

                            send(this.encrypt(Base64.getEncoder().encodeToString(yourBytes)), host, port);
                        }

                        stepCounter = 0;
                        System.out.println("\n\nSẵn sàng nhận yêu cầu mới!.\n\n");
                        break;
                    default:
                        clientSocket.close();
                        break;
                }
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void send (String chuoi, InetAddress host, int port) throws IOException {
        byte[] buffer = chuoi.getBytes();
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length, host, port);
        clientSocket.send(packet);
    }
    
    private void sendByte (byte[] buffer, InetAddress host, int port) throws IOException {
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length, host, port);
        clientSocket.send(packet);
    }
    
    private DatagramPacket receive () throws IOException {
        byte[] buffer = new byte[65507];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        clientSocket.receive(packet);
        return packet;
    }
 
    private String encrypt(String strToEncrypt) 
    {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, clientAESKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } 
        catch (UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
 
    private String decrypt(String strToDecrypt) 
    {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, clientAESKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } 
        catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
}
