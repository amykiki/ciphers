package des;

import java.util.Arrays;

/**
 * 产生DES Key
 * 代码来自http://www.herongyang.com/Cryptography/DES-Algorithm-Key-Schedule.html
 * 添加注释便于理解
 */
public class DESSubkeysTest {
    public static void main(String[] a) {
        try {
            byte[] theKey = getTestKey();
            byte[][] subKeys = getSubkeys(theKey);
//            boolean ok = validateSubkeys(subKeys);
//            System.out.println("DES subkeys test result: "+ok);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Permuted choice 1
     */
    public static final int[] PC1 = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
    };
    /**
     * Permuted choice 2
     */
    public static final int[] PC2 = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };
    /**
     * Left shifts(number of bits to ratate) r1, t2, ..., r16
     */
    public static final int[] SHIFTS = {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    /**
     * @param theKey 64-bit key
     * @return
     * @throws Exception
     * Input:
     *     K: byte[8] key array(8x8)
     *     PC1: Permuted choice 1
     *     PC2: Permuted choice 2
     *     r1, r2, ..., r16: left shifts (rotations)
     * Output:
     *     k1, k2, ..., k16: 16 48-bit round keys
     *
     * Algorithm:
     *     K' = PC1(K), applying permuted choice 1 and returning 56 bits
     *     (C0, D0) = K',  into two 28-bit parts
     *     (C1, D1) = (r1(C0), r1(D0)), shifting to the left
     *     k1 = PC2(C1, D1), applying permuted choice 2 and returng 48 bits
     *     (C2, D2) = (r1(C1), r1(D1)), shifting to the left
     *     k2 = PC2(C2, D2), applyng permuted choice 2 and returning 48 bits
     *     ...
     *     (C16, D16) = (r1(C15, D15)), shifting to the left
     *     k16 = PC2(C16, D16)
     */
    private static byte[][] getSubkeys(byte[] theKey) throws Exception {
        printBytes(theKey, "Input key");
        int activeKeySize = PC1.length;
        int numOfSubKeys = SHIFTS.length;
        // 把theKey数组(8x8)映射成(7x8)数组
        byte[] activeKey = selectBits(theKey, PC1);
        printBytes(activeKey, "After permuted choice 1 - Active key");
        int halfKeySize = activeKeySize / 2;
        // 把 activeKey数组分成两部分。注意原数组是7x8大小，而分成的是4x8x2两个。在每组数组的第4个byte的后面4位为全0.注意均分的是bit
        // 如 activeKey数组为 11110000 11001100 10101010 11110101 01010110 01100111 10001111
        // 生成的 byte[] c =  11110000 11001100 10101010 11110000
        // 生成的 byte[] d =  01010101 01100110 01111000 11110000
        byte[] c = selectBits(activeKey, 0, halfKeySize);
        byte[] d = selectBits(activeKey, halfKeySize, halfKeySize);
        printBytes(c, "C byte Array");
        printBytes(d, "D byte Array");
        byte[][] subKeys = new byte[numOfSubKeys][];
        for (int k = 0; k < numOfSubKeys; k++) {
            c = rotateLeft(c, halfKeySize, SHIFTS[k]);
            d = rotateLeft(d, halfKeySize, SHIFTS[k]);
            byte[] cd = concatenateBits(c, halfKeySize, d, halfKeySize);
            printBytes(cd, "Subkey #" + (k + 1) + " after shifting");
            subKeys[k] = selectBits(cd, PC2);
            printBytes(subKeys[k], "Subkey #" + (k + 1)
                    + " after permuted choice 2");
        }
        return subKeys;
    }

    private static byte[] selectBits(byte[] in, int pos, int len) {
        int numOfBytes = (len-1)/8 + 1;
        byte[] out = new byte[numOfBytes];
        for (int i=0; i<len; i++) {
            int val = getBit(in,pos+i);
            setBit(out,i,val);
        }
        return out;
    }

    /**
     * @param in  原始8 bytes key数组
     * @param map 映射map
     * @return
     */
    private static byte[] selectBits(byte[] in, int[] map) {
        int numOfBytes = (map.length-1)/8 + 1;
        byte[] out = new byte[numOfBytes];
        for (int i=0; i<map.length; i++) {
            int val = getBit(in, map[i] - 1);
            setBit(out,i,val);
        }
        return out;
    }

    /**
     * @param data  原始8 bytes key数组
     * @param pos 映射位置
     * @return 选取的bit位
     * posBit是按照从左到右来计算的。
     */
    private static int getBit(byte[] data, int pos) {
        int posByte = pos/8;
        int posBit = pos%8;
        byte valByte = data[posByte];
        int valInt = valByte>>(8-(posBit+1)) & 0x0001;
        // debug
        /*byte dNum = (byte) (valByte >> (8 - (posBit + 1)));
        System.out.println("posBit = " + posBit);
        System.out.println("valByte = " + byteToBits(valByte));
        System.out.println("dNum = " + byteToBits(dNum));
        System.out.println("valInt = " + valInt);*/
        return valInt;
    }

    /**
     * @param data
     * @param pos 偏移量
     * @param val
     * 按照从左到右来计算的。
     */
    private static void setBit(byte[] data, int pos, int val) {
        int posByte = pos/8;
        int posBit = pos%8;
        byte oldByte = data[posByte];
        oldByte = (byte) (((0xFF7F>>posBit) & oldByte) & 0x00FF);
        byte newByte = (byte) ((val<<(8-(posBit+1))) | oldByte);
        data[posByte] = newByte;
        // debug
        /*byte dBit = (byte) (0xFF7F>>posBit);
        byte dNum = (byte) (val << (8 - (posBit + 1)));
        System.out.println("posBit = " + posBit);
        System.out.println("dBit = " + byteToBits(dBit));
        System.out.println("val = " + val);
        System.out.println("dNum = " + byteToBits(dNum));
        System.out.println("oldByte = " + byteToBits(oldByte));
        System.out.println("newByte = " + byteToBits(newByte));*/
    }
    private static void printBytes(byte[] data, String name) {
        System.out.println("");
        System.out.println(name+":");
        for (int i=0; i<data.length; i++) {
            System.out.print(byteToBits(data[i])+" ");
        }
        System.out.println();
    }
    private static String byteToBits(byte b) {
        StringBuffer buf = new StringBuffer();
        for (int i=0; i<8; i++)
            buf.append((int)(b>>(8-(i+1)) & 0x0001));
        return buf.toString();
    }

    /**
     * @return byte[8] key array
     */
    private static byte[] getTestKey() {
        String strKey = " 00010011 00110100 01010111 01111001"
                +" 10011011 10111100 11011111 11110001";
        byte[] theKey = new byte[8];
        for (int i=0; i<8; i++) {
            String strByte = strKey.substring(9*i+1,9*i+1+8);
            theKey[i] = (byte) Integer.parseInt(strByte,2);
        }
        return theKey;
    }
}
