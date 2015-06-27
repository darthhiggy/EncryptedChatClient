package com.company;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.net.Socket;

/**
 * Created by Michael on 6/23/2015.
 */
public class Send implements Runnable
{
    byte[] iv;
    SecretKey sessionKey;
    Socket socket;

    public Send(byte[] ivB, SecretKey sKey, Socket skt)
    {
        iv = ivB;
        sessionKey = sKey;
        socket = skt;
    }

    @Override
    public void run()
    {
        try {
            //now use tha that session key and IV to create a CipherInputStream. We will use them to read all character
            //that are sent to us by the client

            System.out.println("Creating the cipher stream ...");
            Cipher encrypter = Cipher.getInstance("DESede/CFB8/NoPadding");
            IvParameterSpec spec = new IvParameterSpec(iv);
            encrypter.init(Cipher.ENCRYPT_MODE, sessionKey, spec);
            CipherOutputStream cipherOut = new CipherOutputStream(socket.getOutputStream(), encrypter);

            //we are connected securely. we can now send data to sever, which we gather from the keyboard

            String testString = "Established Connection \n\n";
            byte[] byteArray = testString.getBytes();
            cipherOut.write(byteArray);

            //now send everything the user types
            int theCharacter = 0;
            theCharacter = System.in.read();
            while(theCharacter != '~') //~ is an escape character to exit
            {
                cipherOut.write(theCharacter);
                theCharacter = System.in.read();
            }
           // cipherOut.close();

        } catch(Exception e)
        {
            e.printStackTrace();
        }
        {

        }
    }
}
