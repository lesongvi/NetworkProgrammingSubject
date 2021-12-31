/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CommonModels;

import java.io.Serializable;
import java.util.ArrayList;

/**
 *
 * @author ADMIN
 */
public class TextPack implements Serializable {
    private ArrayList<TextProcessing> TxtPArray;
    
    public TextPack () {
        this(new ArrayList<TextProcessing>());
    }
    
    public TextPack (ArrayList<TextProcessing> TxtPArray) {
        this.TxtPArray = TxtPArray;
    }
    
    public TextPack setTextPack (ArrayList<TextProcessing> TxtPArray) {
        this.TxtPArray = TxtPArray;
        return this;
    }
    
    public ArrayList<TextProcessing> getTextPack () {
        return this.TxtPArray;
    }
}
