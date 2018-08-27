// ����Ǯ���ļ�
package purse;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class EPFile {
    private KeyFile keyFile;
    
    // �ڲ�����Ԫ
    // ����Ǯ�����
    private byte[] EP_balance;
    // ����Ǯ���ѻ�������ţ��������
    private byte[] EP_offline;
    // ����Ǯ������������ţ�Ȧ�����
    private byte[] EP_online;
    
    // ��Կ�汾��
    byte keyID;
    // �㷨��ʶ
    byte algID;
    
    // ���������
    private Randgenerator randGen;
    // ���ݼӽ��ܷ�ʽʵ��
    private PenCipher penCipher;

    // ��ʱ��������
    // 4�ֽ���ʱ��������
    private byte[] tmp1;           
    private byte[] tmp2;
    // 8�ֽ���ʱ��������
    private byte[] tmp3;
    private byte[] tmp4;
    // 32�ֽ���ʱ��������
    private byte[] tmp5;
    private byte[] tmp6;
    

    public EPFile(KeyFile keyFile) {
        // ��ʼ��Ϊ0
        // ��� 4�ֽ�
        EP_balance = new byte[4];
        Util.arrayFillNonAtomic(EP_balance, (short)0, (short)4, (byte)0x00);
        // �ѻ�������� 2�ֽ�
        EP_offline = new byte[2];
        Util.arrayFillNonAtomic(EP_offline, (short)0, (short)2, (byte)0x00);
        // ����������� 2�ֽ�
        EP_online = new byte[2];
        Util.arrayFillNonAtomic(EP_online, (short)0, (short)2, (byte)0x00);
        
        this.keyFile = keyFile;
        
        // ���ٿռ�
        tmp1 = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
        tmp2 = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
        tmp3 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
        tmp4 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
        tmp5 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        tmp6 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);

        // ʵ����
        randGen = new Randgenerator();
        penCipher = new PenCipher();
    }
    

    // ���ӵ���Ǯ�����
    // data�����ӵĽ�flag���Ƿ�������ӣ�����ֻ��Ȧ���ʼ����
    // ���أ�Ȧ�������Ƿ񳬹�����޶�
    public final short increase(byte[] data, boolean flag) {
        short i, t1, t2, lim;
        lim = (short)0;
        for (i=3; i>=0; i--) {
            // EP_balance[(short)i]��data[i]��Ϊ1�ֽڣ�t1��t2��short����2�ֽڣ���0xFF
            t1 = (short)(EP_balance[(short)i]&0xFF);
            t2 = (short)(data[i]&0xFF); 
            t1 = (short)(t1+t2+lim);
            // �����ӣ��޸����
            if (flag)
                EP_balance[(short)i] = (byte)(t1%256);
            lim = (short)(t1/256);
        }
        // �����ʾ��������޶�
        return lim;
    }
    // Ȧ���ʼ��
    // num����Կ��¼�ţ�data��������е����ݶ�
    // ���أ�0ִ�гɹ���2����
    public final short init4load(short num, byte[] data) {
        short len, rc;
        // �ж��Ƿ񳬶�Ȧ��
        // �μ�ʵ��4�ĵ�-Ȧ���ʼ��-�����-Data��
        // ���׽�����tmp2
        Util.arrayCopyNonAtomic(data, (short)1, tmp2, (short)0, (short)4);
        // �ն˻���Ŵ���tmp3
        Util.arrayCopyNonAtomic(data, (short)5, tmp3, (short)0, (short)6);
        // tmp2��ǰ��Ž��׽��ж��Ƿ񳬶�
        rc = increase(tmp2, false);
        if (rc != (short)0)
            return (short)2;
        
        // ����Ȧ����Կ
        // len����Կ���ȣ�num����Կ��¼�ţ�tmp6�������Կ�Ļ�����
        len = keyFile.readkey(num, tmp6);
        // ����Կ�л�ȡ��Կ�汾�ź��㷨��ʶ����Կ�ļ��ṹ�μ�ʵ���ĵ�2
        keyID = tmp6[3];
        algID = tmp6[4];
        // ����֮ǰ�����ļ���Ȧ����Կֵ������tmp5
        Util.arrayCopyNonAtomic(tmp6, (short)5, tmp5, (short)0, len);
        // ���ɹ�����Կ
        // �������������tmp6��tmp[0][1][2][3]��������
        randGen.GenerateSecureRnd();
        randGen.GetRndValue(tmp6, (short)0);
        // �����������к�EP_online��ֵ��tmp6[4][5]
        Util.arrayCopyNonAtomic(EP_online, (short)0, tmp6, (short)4, (short)2);
        // ��ȫ����Ϊ���ɹ�����Կ���������ݣ��������ݸ�ʽ�μ�ʵ��4�ĵ�-����Ǯ���������-Ȧ��-1-2
        tmp6[6] = (byte)0x80;
        tmp6[7] = (byte)0x00;
        // tmp5��ǰ�����Կ��tmp6��ǰ���α�����+�����������к�EP_online+8000�����ɹ�����Կ����tmp4
        penCipher.gen_processkey(tmp5, tmp6, (short)0, (short)8, tmp4, (short)0); 
        // ����MAC1
        // ����Ǯ�����EP_balance����tmp6[0][1][2][3]
        Util.arrayCopyNonAtomic(EP_balance, (short)0, tmp6, (short)0, (short)4);
        // ���׽�����tmp6[4][5][6]][7]
        Util.arrayCopyNonAtomic(data, (short)1, tmp6, (short)4, (short)4);
        // �������ͱ�ʶ0x02����tmp6[8]
        tmp6[8] = (byte)0x02;
        // �ն˻���ŷ���tmp6[9][10][11][12][13][14]
        Util.arrayCopyNonAtomic(data, (short)5, tmp6, (short)9, (short)6);
        // ����MAC1������tmp1
        // tmp4��ǰ��Ź�����Կ��tmp6��ǰ��� ��ǰ����Ǯ�����EP_balance+���׽��+�������ͱ�ʶ0x02+�ն˻����
        penCipher.gen_ac(tmp4, tmp6, (short)0x0F, tmp1);
        // IC��������Ӧ����
        // ��Ӧ������μ�ʵ��4�ĵ�-����Ǯ�����������-Ȧ���ʼ��-��Ӧ����������
        // ����Ǯ��������data[0][1][2][3]
        Util.arrayCopyNonAtomic(EP_balance, (short)0, data, (short)0, (short)4);
        // ����Ǯ�������������EP_online����data[4][5]
        //ISOException.throwIt((byte)data.length);
        Util.arrayCopyNonAtomic(EP_online, (short)0, data,  (short)4, (short)2);
        //ISOException.throwIt((byte)data.length);
        // ��Կ�汾�Ŵ���data[6]
        data[6] = keyID;
        // �㷨��ʶ����data[7]
        data[7] = algID;
        // ���������data[8][9][10][11]
        //ISOException.throwIt((byte)data.length);
        //bug!!!!!
        randGen.GetRndValue(data, (short)8);
        // ��MAC1����data[12][13][14][15];
        Util.arrayCopyNonAtomic(tmp1, (short)0, data, (short)12, (short)4);
        return 0;
    }
    // Ȧ��
    // data��������е����ݶ�
    // ���أ�0Ȧ������ִ�гɹ���1MAC2У�����2Ȧ�泬������޶3��Կδ�ҵ�
    public final short load(byte[] data) {
        short rc, len, num;
        
        // IC�����ù�����Կ����MAC2���ٸ��ն˴�������MAC2��֤����ͬ��MAC2��Ч
        // data����������ݶΣ��μ�ʵ���ĵ�4-����Ǯ���������-Ȧ��-3
        // ��tmp6�������MAC2���������ݣ����׽��+���ױ�ʶ+�ն˻����+�������ڣ�������+����ʱ�䣨������
        // tmp2��ǰ��Ž��׽�����tmp6[0][1][2][3]
        Util.arrayCopyNonAtomic(tmp2, (short)0, tmp6, (short)0, (short)4);       
        // ���ױ�ʶ0x02����tmp6[4]
        tmp6[4] = (byte)0x02;                                                       
        // tmp3��ǰ����ն˻���ţ�����tmp6[5][6][7][8][9][10]
        Util.arrayCopyNonAtomic(tmp3, (short)0, tmp6, (short)5, (short)6);       
        // ����������ʱ�����tmp6[11][12][13][14][15][16][17]
        Util.arrayCopyNonAtomic(data, (short)0, tmp6, (short)11, (short)7);         
        // tmp6����18�����ɵ�MAC2����tmp1
        penCipher.gen_ac(tmp4, tmp6, (short)18, tmp1);
        // ����MAC2�����󷵻�1
        // arrayCompare(byte[] src, short srcOff, byte[] dest, short destOff, short length) 
        // data[7][8][9][10]��������е�MAC2��tmp1�����IC�����ɵ�MAC2
        if (Util.arrayCompare(data, (short)7, tmp1, (short)0, (short)4) != (byte)0x00)
            return (short)1;
        
        // ����Ǯ���������
        rc = increase(tmp2, true);
        if(rc != (short)0)
            return (short)2;
        
        // ����TAC�����ظ��ն�
        // ��tmp6�������TAC���������ݣ�����Ǯ�������׺�+����Ǯ������������ţ��ӣ�ǰ��+���׽��+�������ͱ�ʶ+�ն˻����+�������ڣ�������+����ʱ�䣨������
        // ����Ǯ�����EP_balance����tmp6[0][1][2][3]
        Util.arrayCopyNonAtomic(EP_balance, (short)0, tmp6, (short)0, (short)4);
        // �����������EP_online����tmp[4][5]
        Util.arrayCopyNonAtomic(EP_online, (short)0, tmp6, (short)4, (short)2);
        // tmp2��ǰ��Ž��׽�����tmp6[6][7][8][9]
        Util.arrayCopyNonAtomic(tmp2, (short)0, tmp6, (short)6, (short)4);
        // �������ʹ���tmp6[10]
        tmp6[10] = (byte)0x02;
        // tmp3��ǰ����ն˻���ţ�����tmp6[11][12][13][14][15][16]
        Util.arrayCopyNonAtomic(tmp3, (short)0, tmp6, (short)11, (short)6);
        // ����������ʱ�����tmp6[17][18][19][20][21][22][23]
        Util.arrayCopyNonAtomic(data, (short)0, tmp6, (short)17, (short)7);
        
        // �����������EP_online��1��������������ΪTAC��Ҫ�����������У��������������Ҫ����+1ǰ������
        rc = Util.makeShort(EP_online[0], EP_online[1]);
        rc++;
        if (rc > (short)256)
            rc = (short)1;
        Util.setShort(EP_online, (short)0, rc);
        
        // ����TAC
        // num����¼�ţ�tmp5����Կ���봦��len����Կ����
        // 0x34��ӦTAC��Կ����
        num = keyFile.findKeyByType((byte)0x34);
        len = keyFile.readkey(num, tmp5);
        // ����Ϊ0������������Կ
        if (len == 0)
            return (short)3;
        // ȥ��ǰ��λTAC��Կͷ�����õ���TAC��Կֵ����tmp4��
        Util.arrayCopyNonAtomic(tmp5, (short)5, tmp4, (short)0, (short)8);
        // TAC��Կ����8���ֽڣ�tmp4��������8���ֽڣ�tmp5[13]...����򣬽������tmp5�У���Ϊtmp5[13][14][15][16][17][18][19][20]
        penCipher.xor_8byte(tmp4, tmp5, (short)13);
        // tmp5[13][14][15][16][17][18][19][20]������TAC��Ҫ����Կֵ������tmp��
        byte[] tmp = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(tmp5, (short)13, tmp, (short)0, (short)8);
        // ����TAC������data
        penCipher.gen_ac(tmp, tmp6, (short)24, data);
        return (short)0;
    }
    

    // ���ٵ���Ǯ�����
    // data�����ٵĽ�flag���Ƿ���ļ��٣�����ֻ�����ѳ�ʼ����
    // ���أ����Ѻ��Ƿ񳬶�
    public final short decrease(byte[] data, boolean flag) {
        short i, t1, t2, lim;
        lim = (short)0;
        for (i=3; i>=0; i--) {
            // EP_balance[(short)i]��data[i]��Ϊ1�ֽڣ�t1��t2��short����2�ֽڣ���0xFF
            t1 = (short)(EP_balance[(short)i]&0xFF);
            t2 = (short)(data[i]&0xFF);
            if (t2>t1)
                lim = (short)1;
            t1 = (short)(t1-t2-lim);
            if (flag)
                EP_balance[(short)i] = (byte)(t1 % 256);
        }
        return lim;
    }
    // ���ѳ�ʼ��
    // num����Կ��¼�ţ�data��������е����ݶ�
    // ���أ�0ִ�гɹ���2����
    public final short init4purchase(short num, byte[] data) {
        short len, rc;
        // �ж��Ƿ񳬶�����
        // �μ�ʵ��4�ĵ�-���ѳ�ʼ��-�����-Data��
        // ���׽�����tmp2
        Util.arrayCopyNonAtomic(data, (short)1, tmp2, (short)0, (short)4);
        // �ն˻���Ŵ���tmp3
        Util.arrayCopyNonAtomic(data, (short)5, tmp3, (short)0, (short)6);
        // tmp2��ǰ��Ž��׽��ж��Ƿ񳬶�
        rc = decrease(tmp2, false);
        if(rc != (short)0)
            return (short)2;
        
        // ����������Կ
        // len����Կ���ȣ�num����Կ��¼�ţ�tmp6�������Կ�Ļ�����
        len = keyFile.readkey(num, tmp6);
        // ����Կ�л�ȡ��Կ�汾�ź��㷨��ʶ����Կ�ļ��ṹ�μ�ʵ���ĵ�2
        
        keyID = tmp6[3];
        algID = tmp6[4];
        // ����֮ǰ�����ļ���������Կֵ������tmp5
       
        Util.arrayCopyNonAtomic(tmp6, (short)5, tmp5, (short)0, len);
        
        // ���������������tmp6
        randGen.GenerateSecureRnd();
        randGen.GetRndValue(tmp6, (short)0);
        // ������Ӧ����
        // ������μ�ʵ��4�ĵ�-����Ǯ�����������-���ѳ�ʼ��-��Ӧ����������
        // ����Ǯ�����EP_balance����data[0][1][2][3]
        Util.arrayCopyNonAtomic(EP_balance, (short)0, data, (short)0, (short)4);
        // �ѻ��������EP_offline����data[4][5]
        Util.arrayCopyNonAtomic(EP_offline, (short)0, data,  (short)4, (short)2);
        // ͸֧�޶����data[6][7][8]
        // arrayFillNonAtomic(byte[] bArray, short bOff, short bLen, byte bValue) 
        Util.arrayFillNonAtomic(data, (short)6, (short)3, (byte)0x00);
        // ��Կ�汾�Ŵ���data[9]
        data[9] = keyID;
        // �㷨��ʶ����data[10]
        data[10] = algID;
        // �����������data[11][12][13][14]
        randGen.GetRndValue(data, (short)11);
        return 0;
        
    }
    // ��������
    // data��������е����ݶ�
    // ���أ�0����ִ�гɹ���1MACУ�����2���ѳ��3δ�ҵ���Կ
    public final short purchase(byte[] data) {
        short rc, len, num;

        // tmp5��ǰ���������Կֵ
        // tmp6��ǰ��������

        // ���ɹ�����Կ
        // tmp6������ɹ�����Կ���������ݣ�α�����+����Ǯ���ѻ��������+�ն˽�����ŵ����������ֽ�
        // �ѻ��������к�EP_offline����tmp6[4][5]
        Util.arrayCopyNonAtomic(EP_offline, (short)0, tmp6, (short)4, (short)2);
        // �ն˽�����ź����ֽڴ���tmp6[6][7]
        Util.arrayCopyNonAtomic(data, (short)2, tmp6, (short)6, (short)2);
        // ���ɹ�����Կ������tmp4
        penCipher.gen_processkey(tmp5, tmp6, (short)0, (short)8, tmp4, (short)0);
        
        // IC�����ù�����Կ����MAC1���ٸ��ն˴�������MAC1��֤����ͬ��MAC1��Ч
        // �������ݣ����׽��||�������ͱ�ʶ(0x06)||�ն˻����||�������ڣ�������||����ʱ�䣨������
        // ���׽�����tmp6[0][1][2][3]
        Util.arrayCopyNonAtomic(tmp2, (short)0, tmp6, (short)0, (short)4);
        // ���ױ�ʶ����tmp6[4]
        tmp6[4] = (byte)0x07;
        // �ն˻���Ŵ���tmp6[5][6][7][8][9][10]
        Util.arrayCopyNonAtomic(tmp3, (short)0, tmp6, (short)5, (short)6);
        // �������ں�ʱ�����tmp6[11][12][13][14][15][16][17]
        Util.arrayCopyNonAtomic(data, (short)4, tmp6, (short)11, (short)7);
        // tmp4��ǰ��Ź�����Կ��tmp6��ǰ����������ݣ�����MAC1����tmp1
        penCipher.gen_ac(tmp4, tmp6, (short)18, tmp1);
        
        // ����MAC1������ͬ����1
        // data[11][12][13][14]��������е�MAC1
        if (Util.arrayCompare(data, (short)11, tmp1, (short)0, (short)4) != (byte)0x00)
            return (short)1;
        
        // �ѻ�������ż�1
        rc = Util.makeShort(EP_offline[0], EP_offline[1]);
        rc++;
        if (rc > (short)256)
            rc = (short)1;
        Util.setShort(EP_offline, (short)0, rc);
        
        // ����Ǯ��������
        rc = decrease(tmp2, true);
        if(rc != (short)0)
            return (short)2;
    
        // MAC2����
        // ���׽����Ϊ��������tmp6[0]~[3]
        Util.arrayCopyNonAtomic(tmp2, (short)0, tmp6, (short)0, (short)4);           
        // tmp4Ϊ������Կ��tmp6Ϊ�������ݣ��õ�MAC2����tmp1�����޸�����tmp6��������Ҫʹ��tmp6
        penCipher.gen_ac(tmp4, tmp6, (short)4, tmp1);
        
        // ����TAC�����ظ��ն�
        // tmp6�������TAC���������ݣ����׽��+�������ͱ�ʶ+�ն˻����+�ն˽������+�������ڣ�������+����ʱ�䣨������
        // ���׽�����tmp6[0][1][2][3]
        Util.arrayCopyNonAtomic(tmp2, (short)0, tmp6, (short)0, (short)4);
        // �������ͱ�ʶ����tmp6[4]
        tmp6[4] = (byte)0x06;
        // �ն˻���Ŵ���tmp6[5][6][7][8][9][10]
        Util.arrayCopyNonAtomic(tmp3, (short)0, tmp6, (short)5, (short)6);
        // �ն˽�����Ŵ���tmp6[11][12][13][14]
        Util.arrayCopyNonAtomic(data, (short)0, tmp6, (short)11, (short)4);
        // ����������ʱ�����tmp6[15][16][17][18][19][20][21]
        Util.arrayCopyNonAtomic(data, (short)4, tmp6, (short)15, (short)7);
        // ����TAC
        // num����¼�ţ�tmp5����Կ���봦��len����Կ����
        // 0x34��ӦTAC��Կ����
        num = keyFile.findKeyByType((byte)0x34);
        len = keyFile.readkey(num, tmp5);
        // ����Ϊ0������������Կ
        if (len == 0)
            return (short)3;
        // ȥ��ǰ��λTAC��Կͷ�����õ���TAC��Կֵ����tmp4��
        Util.arrayCopyNonAtomic(tmp5, (short)5, tmp4, (short)0, (short)8);
        // TAC��Կ����8���ֽڣ�tmp4��������8���ֽڣ�tmp5[13]...����򣬽������tmp5�У���Ϊtmp5[13][14][15][16][17][18][19][20]
        penCipher.xor_8byte(tmp4, tmp5, (short)13);
        // tmp5[13][14][15][16][17][18][19][20]������TAC��Ҫ����Կֵ������tmp��
        byte[] tmp = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(tmp5, (short)13, tmp, (short)0, (short)8);
        // MAC2����data[4][5][6][7]
        Util.arrayCopyNonAtomic(tmp1, (short)0, data, (short)4, (short)4);
        // ����TAC������data[0][1][2][3]
        // tmpΪ������Կֵ��tmp6Ϊ�������ݣ��ᱻ�޸�
        penCipher.gen_ac(tmp, tmp6, (short)22, data);
        return 0;
    }


    // ��ȡ����Ǯ�����
    // data������Ǯ�����Ļ�����
    public final short get_balance(byte[] data) {
        return Util.arrayCopyNonAtomic(EP_balance, (short)0, data, (short)0, (short)4);
    }
}