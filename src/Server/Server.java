/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Server;

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
public class Server extends Thread {
    private ServerSocket serverSocket;
    private DatagramSocket clientSocket;
    private String name;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey, publicKeyofClient;
    private KeyPair keyPair;
    private KeyPairGenerator keyPairGenerator;
    private int stepCounter = 0;
    private String message = null;
    private Helper helper = new Helper();
    private int keysize = 2048;
    private SecretKey clientAESKey;
    
    public static void main (String [] args) throws IOException {
        new Server(7778).start();
    }
   
    public Server(int port) throws IOException {
        clientSocket = new DatagramSocket(port);
        this.name = name;
        new Thread(this).run();
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
                        // Nhận khóa công khai của Client

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

                        send(this.encrypt(this.charCount(this.decrypt(message))), host, port);

                        stepCounter = 0;
                        System.out.println("\n\nSẵn sàng nhận yêu cầu mới!.\n\n");
                        break;
                    default:
                        clientSocket.close();
                        break;
                }
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
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
    
    private String charCount (String msg) {
        msg = this.helper.RemoveVNSign(msg);
        char[] alp = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
        String lastTxt = "";
        long count = 0;
        int total = 0;
        for (char alStr : alp) {
            count = msg.chars().filter(ch -> Character.toLowerCase((char)ch) == Character.toLowerCase(alStr)).count();
            if (count != 0)
                lastTxt += "Chữ cái " + alStr + " xuất hiện " + count + " lần.\n";
            total += count;
        }
        
        lastTxt = "Tổng cộng có " + total + " chữ cái, trong đó:\n" + lastTxt;
        
        return lastTxt;
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
