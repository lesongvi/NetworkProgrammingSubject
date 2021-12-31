/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Server.Utils;

import CommonModels.TextProcessing;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.*;
import java.util.regex.*;
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
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        byte[] key = viKey.getBytes("UTF-8");

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
    
    public ArrayList<TextProcessing> charCount (String msg) {
        msg = this.RemoveVNSign(msg);
        char[] alp = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
        String lastTxt = "";
        long count = 0;
        int total = 0;
        ArrayList<TextProcessing> tpArr = new ArrayList<>();
        for (char alStr : alp) {
            count = msg.chars().filter(ch -> Character.toLowerCase((char)ch) == Character.toLowerCase(alStr)).count();
            if (count != 0)
                tpArr.add(new TextProcessing(alStr, (int) count));
            total += count;
        }
        
        return tpArr;
    }
}
