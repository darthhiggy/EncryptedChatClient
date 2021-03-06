package com.company;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Main
{

    /**
     *	Static variables for 1024 bit Diffie-Hellman algorithm.
     *
     *	This is required to have matching moduli between client
     *	and server.
     *
     */
    private static final byte SKIP_1024_MODULUS_BYTES[] = {
            (byte)0xF4, (byte)0x88, (byte)0xFD, (byte)0x58,
            (byte)0x4E, (byte)0x49, (byte)0xDB, (byte)0xCD,
            (byte)0x20, (byte)0xB4, (byte)0x9D, (byte)0xE4,
            (byte)0x91, (byte)0x07, (byte)0x36, (byte)0x6B,
            (byte)0x33, (byte)0x6C, (byte)0x38, (byte)0x0D,
            (byte)0x45, (byte)0x1D, (byte)0x0F, (byte)0x7C,
            (byte)0x88, (byte)0xB3, (byte)0x1C, (byte)0x7C,
            (byte)0x5B, (byte)0x2D, (byte)0x8E, (byte)0xF6,
            (byte)0xF3, (byte)0xC9, (byte)0x23, (byte)0xC0,
            (byte)0x43, (byte)0xF0, (byte)0xA5, (byte)0x5B,
            (byte)0x18, (byte)0x8D, (byte)0x8E, (byte)0xBB,
            (byte)0x55, (byte)0x8C, (byte)0xB8, (byte)0x5D,
            (byte)0x38, (byte)0xD3, (byte)0x34, (byte)0xFD,
            (byte)0x7C, (byte)0x17, (byte)0x57, (byte)0x43,
            (byte)0xA3, (byte)0x1D, (byte)0x18, (byte)0x6C,
            (byte)0xDE, (byte)0x33, (byte)0x21, (byte)0x2C,
            (byte)0xB5, (byte)0x2A, (byte)0xFF, (byte)0x3C,
            (byte)0xE1, (byte)0xB1, (byte)0x29, (byte)0x40,
            (byte)0x18, (byte)0x11, (byte)0x8D, (byte)0x7C,
            (byte)0x84, (byte)0xA7, (byte)0x0A, (byte)0x72,
            (byte)0xD6, (byte)0x86, (byte)0xC4, (byte)0x03,
            (byte)0x19, (byte)0xC8, (byte)0x07, (byte)0x29,
            (byte)0x7A, (byte)0xCA, (byte)0x95, (byte)0x0C,
            (byte)0xD9, (byte)0x96, (byte)0x9F, (byte)0xAB,
            (byte)0xD0, (byte)0x0A, (byte)0x50, (byte)0x9B,
            (byte)0x02, (byte)0x46, (byte)0xD3, (byte)0x08,
            (byte)0x3D, (byte)0x66, (byte)0xA4, (byte)0x5D,
            (byte)0x41, (byte)0x9F, (byte)0x9C, (byte)0x7C,
            (byte)0xBD, (byte)0x89, (byte)0x4B, (byte)0x22,
            (byte)0x19, (byte)0x26, (byte)0xBA, (byte)0xAB,
            (byte)0xA2, (byte)0x5E, (byte)0xC3, (byte)0x55,
            (byte)0xE9, (byte)0x2F, (byte)0x78, (byte)0xC7
    };

    //In oder to use skip, we need a BigInteger representation of that modulus
    private static final BigInteger MODULUS = new BigInteger(1,SKIP_1024_MODULUS_BYTES);

    //We also need a base for Dittie-Hellman, which SKIP defines as 2
    private static final BigInteger BASE = BigInteger.valueOf(2);

    //we can wrap those two SKIP parameter into one DHParamterSpec, which we'll use to initialize our keyAgreement latger
    private static final DHParameterSpec PARAMETER_SPEC = new DHParameterSpec(MODULUS, BASE);

    public static void main (String[] args) throws Exception
    {
        //prompt user to enter a port number


        //prompt user to enter a port number


        System.out.print("Enter the port number: ");
        Scanner scan = new Scanner(System.in);
        int port = scan.nextInt();
        scan.nextLine();
        System.out.print("Enter the host name: ");
        String hostName = scan.nextLine();

        //Initialize a key pair generator with the SKIP parameters we sepcified, and genrating a pair
        //This will take a while: 5...15 seconrds

        System.out.println("Generating a Diffie-Hellman keypair: ");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(PARAMETER_SPEC);
        KeyPair keyPair = kpg.genKeyPair();
        System.out.println("key pair has been made...");

        //open up a socket and connect to the server

        System.out.println("trying to connect to " + hostName + ", port " + port);
        Socket s = new Socket(hostName, port);

        //create data input stream and opoutputstream

        DataOutputStream out = new DataOutputStream(s.getOutputStream());
        DataInputStream in = new DataInputStream(s.getInputStream());

        //receive the server's public key

        System.out.println("receiving the server's public Key...");
        byte[] keyBytes = new byte[in.readInt()];
        in.readFully(keyBytes);

        KeyFactory kf = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyBytes);
        PublicKey serverPublicKey = kf.generatePublic(x509Spec);
        System.out.println("server public key: " + CryptoUtils.toHex(serverPublicKey.getEncoded()));

        System.out.println("Sending my public key...");
        keyBytes = keyPair.getPublic().getEncoded();
        out.writeInt(keyBytes.length);
        out.write(keyBytes);
        System.out.println("Server public key bytes: " + CryptoUtils.toHex(keyBytes));

        //we can now use the server's public key and
        //our own private key to perform the key agreement

        System.out.println("Performing the key agreement ... ");
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(keyPair.getPrivate());
        ka.doPhase(serverPublicKey, true);

        //need to receive the IV from the server (Step 6)

        byte[] iv = new byte[8];
        in.readFully(iv);

        //generate the DESede key from a Ditte-Hellman generated shared secret. (Step 7)


        byte[] sessionKeyBytes = ka.generateSecret();

        // create the session key

        SecretKeyFactory skf = SecretKeyFactory.getInstance("DESede");
        DESedeKeySpec DESedeSpec = new DESedeKeySpec(sessionKeyBytes);
        SecretKey sessionKey = skf.generateSecret(DESedeSpec);

        //printout session key bytes

        System.out.println("Session key bytes: " + CryptoUtils.toHex(sessionKey.getEncoded()));

        //create a receive runnable class and a send runnable class and create threads for both of them then
        //start both threads

        Send snd = new Send(iv, sessionKey, s);
        Receive rec = new Receive(iv, sessionKey, s);
        Thread outT = new Thread(snd);
        Thread inT = new Thread(rec);
        inT.start();
        outT.start();

        //in.close();
        //out.close();
        //s.close();
    }
}
