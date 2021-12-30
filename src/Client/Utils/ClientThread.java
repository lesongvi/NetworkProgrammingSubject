/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Client.Utils;

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

/**
 *
 * @author Nhóm 9
 */
public class ClientThread extends Thread {
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private SecretKey ClientSecretKey;
    private String ServerRSAPublicKey = null;
    private KeyFactory keyFactory;
    private RSAPublicKey publicKeyOfServer;
    private Helper helper = new Helper();
    private byte[] ClientAES;
    private final int keysize = 2048;
    private PrintWriter out = null;
    private Scanner in = null;
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

            System.out.println("TEST");
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
            
            ServerRSAPublicKey = txtContent;

            Matcher m = this.helper.InfoExtract(txtContent);
            System.out.println(txtContent);

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

            Matcher m = this.helper.InfoExtract(ServerRSAPublicKey);

            if(!m.find()) {
                System.err.println("Dữ liệu không hợp lệ!");
                return;
            }

            String ServerModulus = m.group(1).trim();
            String ServerExponent = m.group(2).trim();
            
            BigInteger modulos = new BigInteger(ServerModulus);
            BigInteger exponent = new BigInteger(ServerExponent);

            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulos, exponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKeyOfServer = (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);

            ClientAES = ClientSecretKey.getEncoded();

            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            
            assert c != null;
            c.init(Cipher.ENCRYPT_MODE, publicKeyOfServer);

            byte[] encodedBytes = c.doFinal(ClientSecretKey.getEncoded());
            
            assert encodedBytes != null;
            
            sendByte(encodedBytes, ipServer, PORT);
            this.startProcess();
        } catch (NoSuchAlgorithmException | IOException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException e) {
            Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, e);
        }
    }
    
    private void startProcess() throws IOException {
        System.out.println("Bước 3");

        receive();

        System.out.println(this.mainText);
        send(this.encrypt(this.mainText), ipServer, PORT);
        DatagramPacket packet = receive();
        String ketqua = new String(packet.getData()).trim();
        lock.notify();
        resultContent = this.decrypt(ketqua);
    }
 
    private String encrypt(String strToEncrypt) 
    {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, ClientSecretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } 
        catch (UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Lỗi khi cố gắng mã hóa: " + e.toString());
        }
        return null;
    }
 
    private String decrypt(String strToDecrypt) 
    {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, ClientSecretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } 
        catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Lỗi khi cố gắng giải mã: " + e.toString());
        }
        return null;
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
