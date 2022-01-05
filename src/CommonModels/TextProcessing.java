/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CommonModels;

import java.io.Serializable;

/**
 *
 * @author Nhóm 9 - Lê Song Vĩ - Nguyễn Hữu Minh
 */
public class TextProcessing implements Serializable {
    private char Character;
    private int ATime;
    
    public TextProcessing (char Character, int ATime) {
        this.Character = Character;
        this.ATime = ATime;
    }
    
    public TextProcessing setChar(char Character) {
        this.Character = Character;
        return this;
    }
    
    public char getChar() {
        return this.Character;
    }
    
    public TextProcessing setATime(char ATime) {
        this.ATime = ATime;
        return this;
    }
    
    public int getATime() {
        return this.ATime;
    }
}
