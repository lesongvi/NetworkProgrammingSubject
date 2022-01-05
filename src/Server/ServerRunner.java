/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Server;

import Server.Utils.ServerThread;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Nhóm 9 - Lê Song Vĩ - Nguyễn Hữu Minh
 */
public class ServerRunner {
    static final int PORT = 7778;
    private DatagramSocket server = null;
    public ServerRunner () {
        try {
            server = new DatagramSocket(PORT);
        } catch (SocketException e) {
            Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, e);
        }
    }
    
    public void startServer() throws IOException {
        System.out.println("Server OK...");
        new ServerThread(server);
    }
    
    public static void main (String[] args) throws IOException {
        new ServerRunner().startServer();
    }
}
