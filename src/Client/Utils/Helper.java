/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Client.Utils;

import CommonModels.*;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author ADMIN
 */
public class Helper {
    private String regx = "modulus:(?:.[\\\\r\\\\n\\\\s]*)(.[0-9]*)(?:\\R(?:\\s*))public exponent:(?:.[\\\\r\\\\n\\\\s]*)(.[0-9]*)";
    
    public Helper () { }

    public Matcher InfoExtract (String msg) {
        Pattern pt = Pattern.compile(regx, Pattern.CASE_INSENSITIVE);
        return pt.matcher(msg);
    }
    
    public SecretKeySpec convertKey(String viKey) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        byte[] key = viKey.getBytes("UTF-8");

        key = sha.digest(key);
        key = Arrays.copyOf(key, 16);

        return new SecretKeySpec(key, "AES");
    }
    
    public String txtPackToText (TextPack txtpack, boolean enableTotal) {
        String lastStr = "";
        for (TextProcessing txtPItem : txtpack.getTextPack()) {
            lastStr += "Chữ cái " + txtPItem.getChar() + " xuất hiện " + txtPItem.getATime() + " lần\n";
        }
        if (enableTotal)
            lastStr = "Tổng cộng có " + txtpack.getTextPack().stream().mapToInt(ch -> ch.getATime()).sum() + " chữ cái trong đầu vào, chi tiết bao gồm:\n" + lastStr;
        return lastStr.trim();
    }
}
