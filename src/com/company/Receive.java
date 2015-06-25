package com.company;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.net.Socket;

/**
 * Created by Michael on 6/20/2015.
 */
public class Receive implements Runnable
{
    byte[] iv;
    SecretKey sessionKey;
    Socket socket;

    public Receive(byte[] ivB, SecretKey sKey, Socket skt) {
        iv = ivB;
        sessionKey = sKey;
        socket = skt;
    }

    public void run() {
        try {
            System.out.println("Creating the cipher stream ...");
            Cipher decrypter = Cipher.getInstance("DESede/CFB8/NoPadding");
            IvParameterSpec spec = new IvParameterSpec(iv);
            decrypter.init(Cipher.DECRYPT_MODE, sessionKey, spec);
            CipherInputStream cipherIn = new CipherInputStream(socket.getInputStream(), decrypter);

            //we just keep reading the input and print int to the screen, until -1 sent over

            int theCharacter = 0;
            theCharacter = cipherIn.read();
            while (theCharacter != -1) {
                System.out.print((char) theCharacter);
                theCharacter = cipherIn.read();

            }
            //once -1 is received we want to close up our stream and exit


            //cipherIn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
