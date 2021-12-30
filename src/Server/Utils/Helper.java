/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Server.Utils;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Nhóm 9
 */
public class Helper {
//    private String regx = "modulus:\\s*(.*)(.[\\r\\n\\s]*)public exponent:\\s*(.*)";
    private String regx = "modulus:(?:.[\\\\r\\\\n\\\\s]*)(.[0-9]*)(?:\\R(?:\\s*))public exponent:(?:.[\\\\r\\\\n\\\\s]*)(.[0-9]*)";
    private final String[] VietnameseSigns = new String[]
    {
        "aAeEoOuUiIdDyY",
        "áàạảãâấầậẩẫăắằặẳẵ",
        "ÁÀẠẢÃÂẤẦẬẨẪĂẮẰẶẲẴ",
        "éèẹẻẽêếềệểễ",
        "ÉÈẸẺẼÊẾỀỆỂỄ",
        "óòọỏõôốồộổỗơớờợởỡ",
        "ÓÒỌỎÕÔỐỒỘỔỖƠỚỜỢỞỠ",
        "úùụủũưứừựửữ",
        "ÚÙỤỦŨƯỨỪỰỬỮ",
        "íìịỉĩ",
        "ÍÌỊỈĨ",
        "đ",
        "Đ",
        "ýỳỵỷỹ",
        "ÝỲỴỶỸ"
    };
    
    public Helper () { }

    public Matcher InfoExtract (String msg) {
        Pattern pt = Pattern.compile(regx, Pattern.CASE_INSENSITIVE);
        return pt.matcher(msg);
    }
    
    public SecretKeySpec convertKey(String viKey) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        SecretKeySpec secretKey;
        byte[] key;

        MessageDigest sha = null;
        key = viKey.getBytes("UTF-8");
        sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16);
        return new SecretKeySpec(key, "AES");
    }
    
    public String RemoveVNSign(String str) {
        for (int i = 1; i < VietnameseSigns.length; i++) {
            for (int j = 0; j < VietnameseSigns[i].length(); j++) {
                char[] VNSign = VietnameseSigns[i].toCharArray(),
                        NoSign = VietnameseSigns[0].toCharArray();
                str = str.replace(VNSign[j], NoSign[i - 1]);
            }
        }
        return str;
    }
}
