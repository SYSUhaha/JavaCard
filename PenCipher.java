// 加解密
package purse;

import javacard.framework.JCSystem;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class PenCipher {
	private Cipher desEngine;
	private Key deskey;
	
	public PenCipher() {
		// 获得加密实例
		desEngine = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		// 生成DES密钥实例
		deskey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
	}
	
	// DES加解密运算
	public final void des_oper(byte[] akey, short kOff, byte[] data, short dOff, short dLen, byte[] r, short rOff, byte mode) {
		// 设置密钥值
        // akey：传入密钥，kOff：密钥偏移量
		((DESKey)deskey).setKey(akey, kOff);
		// 设置加密对象实例
		// mode：加密或解密运算模式 Cipher.MODE_DECRYPT/Cipher.MODE_ENCRYPT
		desEngine.init(deskey, mode);
		// 完成运算
		// data：需加密数据，dOff：需加密数据偏移量，dLen：数据长度，r：加密后数据，rOff：加密后数据偏移量。
		desEngine.doFinal(data, dOff, dLen, r, rOff);
	}
	
	// 生成过程密钥
	// key：密钥，data：需加密数据，dOff：需加密数据偏移量，dLen：需加密数据长度，r：加密后数据，rOff：加密后数据存储偏移量
	public final void gen_processkey(byte[] key, byte[]data, short dOff, short dLen, byte[] r, short rOff) {
		byte[] temp1 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		byte[] temp2 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		// 3DES
        // 密钥左半，8字节
		des_oper(key,(short)0,data,(short)0,dLen,temp1,(short)0,Cipher.MODE_ENCRYPT);
        // 密钥右半，8字节
		des_oper(key,(short)8,temp1,(short)0,dLen,temp2,(short)0,Cipher.MODE_DECRYPT);
        // 密钥左半，8字节
		des_oper(key,(short)0,temp2,(short)0,dLen,r,rOff,Cipher.MODE_ENCRYPT);
	}
	
	// 异或8字节
	// d1&d2： 进行异或操作的数据，d2_off：d2偏移量
	public final void xor_8byte(byte[] d1, byte[] d2, short d2_off) {
		// 两个数据进行异或，异或结果存入d2
		for (short i=0; i<8; i++) {
			d2[d2_off] ^= d1[i];
			d2_off++;
		}
	}
	
	// 数据填充
	
	// data：需填充数据， len：数据长度
	public final short data_padding(byte[] data, short len) {
		// 先填充0x80
		data[len] = (byte)0x80;
		len++;
		// 不是8的倍数，填充0x00
		while(len % 8 != 0) {
			data[len] = (byte)0x00;
			len++;
		}
		// 填充后的字节长度
		// 测试
		// ISOException.throwIt(len);
		return len;
	}
	
	// 生成MAC/TAC
	// key：密钥，data：需加密数据，dLen：需加密数据长度，ac：得到的MAC/TAC
	// data会被修改
	public final void gen_ac(byte[] key, byte[] data, short dLen, byte[] ac) {
        // 初始值设定
        byte[] ini_num = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		// 数据填充
		short new_dLen = data_padding(data,dLen);
		// 确定分割块数
		short num = (short)(new_dLen/8);
		// 异或
		xor_8byte(ini_num, data, (short)0);
		// 密文
		byte[] cipher = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		for (short i=1; i<=num; i++) {
			des_oper(key,(short)0,data,(short)(8*(i-1)),(short)8,cipher,(short)0,Cipher.MODE_ENCRYPT);
			// 流程图，异或早一轮结束，参见PPT第13页
			if(i < num)
				xor_8byte(cipher, data, (short)(8*i));
		}
		// MAC 4字节，参见实验3文档-计算MAC-响应报文数据域
		for(short i=0; i<4; i++)
			ac[i] = cipher[i];
	}
}