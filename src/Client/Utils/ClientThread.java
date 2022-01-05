/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Client.Utils;

import CommonModels.*;
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

/**
 *
 * @author Nhóm 9 - Lê Song Vĩ - Nguyễn Hữu Minh
 */
public class ClientThread extends Thread {
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private SecretKey ClientSecretKey;
    private KeyFactory keyFactory;
    private RSAPublicKey publicKeyOfServer;
    private final Helper helper = new Helper();
    private final int keysize = 2048;
    private DatagramSocket client = null;
    final int PORT = 7778;
    private InetAddress ipServer;
    private String mainText;
    private String aesKeyInput;
    private Integer lock;
    private String resultContent;
    
    public ClientThread () throws IOException {
        this(1);
    }
    
    public ClientThread (Integer lock) throws IOException {
        client = new DatagramSocket();
        ipServer = InetAddress.getByName("localhost");
        this.lock = lock;
    }
    
    public ClientThread setMainText (String mainText) {
        this.mainText = mainText;
        return this;
    }
    
    public String getMainText () {
        return this.mainText;
    }
    
    public ClientThread setAesKey (String aesKeyInput) {
        this.aesKeyInput = aesKeyInput;
        return this;
    }
    
    public String getAesKey () {
        return this.aesKeyInput;
    }
    
    public String getResultContent () {
        return this.resultContent;
    }
    
    @Override
    public void run () {
        try {
            synchronized (lock) {
                this.Step0();
            }
        } catch (IOException ex) {
            Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void Step0 () throws IOException {
        System.out.println("Bước 0");
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            keyPairGenerator.initialize(keysize);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = (RSAPublicKey) keyPair.getPublic();
            privateKey = (RSAPrivateKey) keyPair.getPrivate();

            send(String.valueOf(publicKey), ipServer, PORT);
            
            this.Step1();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void Step1 () throws IOException {
        System.out.println("Bước 1");
        try {
            DatagramPacket packet = receive();
            String txtContent = new String(packet.getData()).trim();

            Matcher m = this.helper.InfoExtract(txtContent);

            if(!m.find()) {
                System.err.println("Dữ liệu không hợp lệ!");
                return;
            }
                        
            String serverModulus = m.group(1).trim();
            String serverExponent = m.group(2).trim();

            BigInteger modulos = new BigInteger(serverModulus);
            BigInteger exponent = new BigInteger(serverExponent);

            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulos, exponent);

            keyFactory = KeyFactory.getInstance("RSA");

            publicKeyOfServer = (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);

            this.Step2();
        } catch (UnknownHostException e) {
            Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, e);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException  e) {
            Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, e);
        }
    }
    
    private void Step2 () throws IOException {
        System.out.println("Bước 2");
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            ClientSecretKey = this.helper.convertKey(this.aesKeyInput);

            Cipher c = Cipher.getInstance("RSA");
            
            assert c != null;
            c.init(Cipher.ENCRYPT_MODE, publicKeyOfServer);

            byte[] encodedBytes = c.doFinal(ClientSecretKey.getEncoded());
            
            assert encodedBytes != null;
            
            sendByte(encodedBytes, ipServer, PORT);
            this.startProcess();
        } catch (NoSuchAlgorithmException | IOException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException  e) {
            Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, e);
        }
    }
    
    private void startProcess() throws IOException {
        System.out.println("Bước 3");

        receive();

        send(this.encrypt(this.mainText), ipServer, PORT);
        DatagramPacket packet = receive();
        
        String fromServerStr = this.decrypt(new String(packet.getData()).trim());
        try (ByteArrayInputStream bis = new ByteArrayInputStream(Base64.getDecoder().decode(fromServerStr));
            ObjectInputStream in = new ObjectInputStream(bis);) {
            TextPack txtPack = (TextPack)in.readObject();
            resultContent = this.helper.txtPackToText(txtPack, true);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        lock.notify();
    }
 
    private String encrypt(String strToEncrypt) 
    {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, ClientSecretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } 
        catch (UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Có lỗi trong quá trình mã hóa: " + e.toString());
        }
        return null;
    }
 
    private String decrypt(String strToDecrypt) 
    {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, ClientSecretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } 
        catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Có lỗi trong quá trình giải mã: " + e.toString());
        }
        return null;
    }
    
    private void sendByPieces (byte[] chuoi, String cmd, InetAddress host, int port, String filename) throws IOException {
        byte[] buffer = chuoi;
        int POFZ = 65507;
        BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(buffer));
        int pof = (int) (buffer.length / POFZ);
        int lastByteLength = (int) (buffer.length % POFZ);
        byte[] bytePart = new byte[POFZ];
        
        if (lastByteLength > 0) {
            pof++;
        }
        
        send(cmd + "@" + filename + " " + buffer.length + " " + pof, host, port);
        
        byte[][] fileBytess = new byte[pof][POFZ];
        int count = 0;
        while (bis.read(bytePart, 0, POFZ) > 0) {
            int tmpCount = count++;
            fileBytess[tmpCount] = new byte[bytePart.length];
            fileBytess[tmpCount] = bytePart;
            bytePart = new byte[POFZ];
        }
        
        System.out.println(count);
        for (int i = 0; i < count; i++) {
            sendByte (fileBytess[i], host, port);
        }
    }
    
    private void send (String chuoi, InetAddress host, int port) throws IOException {
        byte[] buffer = chuoi.getBytes();
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length, host, port);
        client.send(packet);
    }
    
    private void sendByte (byte[] buffer, InetAddress host, int port) throws IOException {
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length, host, port);
        client.send(packet);
    }
    
    private DatagramPacket receive () throws IOException {
        byte[] buffer = new byte[65507];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        client.receive(packet);
        return packet;
    }
}
