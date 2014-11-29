package com.codemonkeylabs.encryptionexample.app;

/**
 * Created by brianplummer on 11/29/14.
 */
public class Util
{
    //helper function that concats two byte arrays
    public static byte[] concat(byte[] first, byte[] second){
        byte[] combined = new byte[first.length + second.length];
        System.arraycopy(first, 0, combined, 0, first.length);
        System.arraycopy(second, 0, combined, first.length, second.length);
        return combined;
    }

}
