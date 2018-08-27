// �ӽ���
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
		// ��ü���ʵ��
		desEngine = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		// ����DES��Կʵ��
		deskey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
	}
	
	// DES�ӽ�������
	public final void des_oper(byte[] akey, short kOff, byte[] data, short dOff, short dLen, byte[] r, short rOff, byte mode) {
		// ������Կֵ
        // akey��������Կ��kOff����Կƫ����
		((DESKey)deskey).setKey(akey, kOff);
		// ���ü��ܶ���ʵ��
		// mode�����ܻ��������ģʽ Cipher.MODE_DECRYPT/Cipher.MODE_ENCRYPT
		desEngine.init(deskey, mode);
		// �������
		// data����������ݣ�dOff�����������ƫ������dLen�����ݳ��ȣ�r�����ܺ����ݣ�rOff�����ܺ�����ƫ������
		desEngine.doFinal(data, dOff, dLen, r, rOff);
	}
	
	// ���ɹ�����Կ
	// key����Կ��data����������ݣ�dOff�����������ƫ������dLen����������ݳ��ȣ�r�����ܺ����ݣ�rOff�����ܺ����ݴ洢ƫ����
	public final void gen_processkey(byte[] key, byte[]data, short dOff, short dLen, byte[] r, short rOff) {
		byte[] temp1 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		byte[] temp2 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		// 3DES
        // ��Կ��룬8�ֽ�
		des_oper(key,(short)0,data,(short)0,dLen,temp1,(short)0,Cipher.MODE_ENCRYPT);
        // ��Կ�Ұ룬8�ֽ�
		des_oper(key,(short)8,temp1,(short)0,dLen,temp2,(short)0,Cipher.MODE_DECRYPT);
        // ��Կ��룬8�ֽ�
		des_oper(key,(short)0,temp2,(short)0,dLen,r,rOff,Cipher.MODE_ENCRYPT);
	}
	
	// ���8�ֽ�
	// d1&d2�� ���������������ݣ�d2_off��d2ƫ����
	public final void xor_8byte(byte[] d1, byte[] d2, short d2_off) {
		// �������ݽ���������������d2
		for (short i=0; i<8; i++) {
			d2[d2_off] ^= d1[i];
			d2_off++;
		}
	}
	
	// �������
	
	// data����������ݣ� len�����ݳ���
	public final short data_padding(byte[] data, short len) {
		// �����0x80
		data[len] = (byte)0x80;
		len++;
		// ����8�ı��������0x00
		while(len % 8 != 0) {
			data[len] = (byte)0x00;
			len++;
		}
		// ������ֽڳ���
		// ����
		// ISOException.throwIt(len);
		return len;
	}
	
	// ����MAC/TAC
	// key����Կ��data����������ݣ�dLen����������ݳ��ȣ�ac���õ���MAC/TAC
	// data�ᱻ�޸�
	public final void gen_ac(byte[] key, byte[] data, short dLen, byte[] ac) {
        // ��ʼֵ�趨
        byte[] ini_num = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		// �������
		short new_dLen = data_padding(data,dLen);
		// ȷ���ָ����
		short num = (short)(new_dLen/8);
		// ���
		xor_8byte(ini_num, data, (short)0);
		// ����
		byte[] cipher = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		for (short i=1; i<=num; i++) {
			des_oper(key,(short)0,data,(short)(8*(i-1)),(short)8,cipher,(short)0,Cipher.MODE_ENCRYPT);
			// ����ͼ�������һ�ֽ������μ�PPT��13ҳ
			if(i < num)
				xor_8byte(cipher, data, (short)(8*i));
		}
		// MAC 4�ֽڣ��μ�ʵ��3�ĵ�-����MAC-��Ӧ����������
		for(short i=0; i<4; i++)
			ac[i] = cipher[i];
	}
}