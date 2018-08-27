package purse;

// import Purse;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Purse extends Applet {
    // ʵ������1
    // �ļ�ϵͳ
    // APDU
    private Papdu papdu;
    // ��Կ�ļ�
    private KeyFile keyFile;
    // Ӧ�û����ļ�
    private BinaryFile cardFile;
    // �ֿ��˻����ļ�
    private BinaryFile personFile;
    // ����Ǯ���ļ�
    private EPFile EPFile;
    // ע��
    public Purse(byte[] bArray, short bOffset, byte bLength) {
        papdu = new Papdu();
        byte aidLen = bArray[bOffset];
        if (aidLen == (byte)0x00)
            register();
        else
            register(bArray, (short)(bOffset+1), aidLen);
    }
    // ��װ
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Purse(bArray, bOffset, bLength);
    }

    
    // ʵ������2
    // ִ��
    public void process(APDU apdu) {
        if (selectingApplet())  return;
        // ȡAPDU�������������ò���֮��ֵ���½�����
        byte[] buf = apdu.getBuffer();
        // ����APDU�����ݶβ�����Data�εĳ���
        short lc = apdu.setIncomingAndReceive();
        // ȡAPDU�������е����ݷŵ�����papdu��
        papdu.cla = buf[ISO7816.OFFSET_CLA];
        papdu.ins = buf[ISO7816.OFFSET_INS];
        papdu.p1 = buf[ISO7816.OFFSET_P1];
        papdu.p2 = buf[ISO7816.OFFSET_P2];
        // �ж�APDU�Ƿ�������ݶ�
        // ����: ��ȡ���ݳ���, ��ֵ��le
        if (papdu.APDUContainData()) {
            papdu.lc = buf[ISO7816.OFFSET_LC];
            Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, papdu.data, (short)0, lc);
            if (ISO7816.OFFSET_CDATA+lc>=buf.length) papdu.le=0;
            else papdu.le = buf[ISO7816.OFFSET_CDATA+lc];
        }
        // ������: ����ҪLC��Data�����ȡ������ԭ����LC����ʵ������LE����
        else {
            papdu.le = buf[ISO7816.OFFSET_LC];
            papdu.lc = 0;
        }
        // �ж��Ƿ���Ҫ�������ݣ�������APDU������
        boolean rc = handleEvent();
        if (rc && papdu.le!=(byte)0) {
            Util.arrayCopyNonAtomic(papdu.data, (short)0, buf, ISO7816.OFFSET_CDATA, (short)papdu.data.length);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, papdu.le);//0,data.length
        }
    }
    // ����&��������
    private boolean handleEvent() {
        // ����INS���з�֧�����������ٶ�INS�����ж�
        switch (papdu.ins) {
            // �ļ�����
            case condef.INS_CREATE_FILE:
                return create_file();
            // д����Կ
            case condef.INS_WRITE_KEY:
                return write_key();
            // д��������ļ�
            case condef.INS_WRITE_BIN:
                return write_bin();
            // ����������ļ�
            case condef.INS_READ_BIN:
                return read_bin();
            // ��ʼ��Ȧ��������
            case condef.INS_NIIT_TRANS:
                // ��ʼ��Ȧ��
                if (papdu.p1 == (byte)0x00)
                    return init_load();
                // ��ʼ������
                if (papdu.p1 == (byte)0x01)
                    return init_purchase();
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            // Ȧ��
            case condef.INS_LOAD:
                return load();
            // ����
            case condef.INS_PURCHASE:
                return purchase();
            // ��ѯ���
            case condef.INS_GET_BALANCE:
                return get_balance();
            // ���Թ�����Կ�㷨
            case condef.INS_GET_SESPK:
            	return test_processkey();
            // ����MAC�㷨
            case condef.INS_GET_MAC:
            	return test_mackey();
        }    
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return false;
    }
    //����
    /*
     * ���Թ�����Կ
     */
    private boolean test_processkey() {
    	short KEY_LEN=16, DATA_LEN=8;
    	byte[] key = new byte[KEY_LEN];
    	Util.arrayCopyNonAtomic(papdu.data, (short)0, key, (short)0, KEY_LEN);
    	byte[] data = new byte[DATA_LEN];
    	Util.arrayCopyNonAtomic(papdu.data, KEY_LEN, data, (short)0, DATA_LEN);
    	PenCipher pc = new PenCipher();
    	pc.gen_processkey(key, data, (short)0, DATA_LEN, papdu.data, (short)0);
		return true;
    }
    /*
     * ����MAC��Կ
     */
    private boolean test_mackey() {
    	short KEY_LEN=8, DATA_LEN=(short) (papdu.lc-KEY_LEN);
    	byte[] key = new byte[KEY_LEN];
    	Util.arrayCopyNonAtomic(papdu.data, (short)0, key, (short)0, KEY_LEN);
    	byte[] data = new byte[DATA_LEN*8];
    	Util.arrayCopyNonAtomic(papdu.data, KEY_LEN, data, (short)0, DATA_LEN);
    	PenCipher pc = new PenCipher();
    	pc.gen_ac(key, data, DATA_LEN, papdu.data);
    	return true;
    }
    // �ļ�����
    private boolean create_file() {
        // �ж�ȡֵ�μ�ʵ���ĵ�2������Data��Byte1ȷ���ļ�����
        switch (papdu.data[0]) {
            // ����Ǯ���ļ�
            case condef.EP_FILE:
                return ep_file();
            // ��Կ�ļ���Ӧ�����ȴ���
            case condef.KEY_FILE:
                return key_file();
            // Ӧ�û����ļ�
            case condef.CARD_FILE:
                return card_file();
            // �ֿ��˻����ļ�
            case condef.PERSON_FILE:
                return person_file();
            default: 
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        return true;
    }
    // ��������Ǯ���ļ����μ�ʵ���ĵ�2
    private boolean ep_file() {
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x18)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // �ظ�����
        if (EPFile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // û����Կ�ļ�
        if (keyFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        this.EPFile = new EPFile(keyFile);
        return true;
    }
    // ������Կ�ļ����μ�ʵ���ĵ�2
    private boolean key_file() {
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x00)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // �ظ�����
        if (keyFile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        this.keyFile = new KeyFile();
        return true;
    }
    // ����Ӧ�û����ļ����μ�ʵ���ĵ�2
    private boolean card_file() {
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x16)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // �ظ�����
        if (cardFile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // û����Կ�ļ�
        if (keyFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // ����Ҫд�������
        this.cardFile = new BinaryFile(papdu.data);
        return true;
    }
    // �����ֿ�����Ϣ�ļ����μ�ʵ���ĵ�2
    private boolean person_file() {
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x17)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // �ظ�����
        if (personFile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // û����Կ�ļ�
        if (keyFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // ����Ҫд�������
        this.personFile = new BinaryFile(papdu.data);
        return true;
    }
    // д����Կ���μ�ʵ���ĵ�2
    private boolean write_key() {
        // û����Կ�ļ�
        if (keyFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        // ==0x00������==0x01�޸�
        if (papdu.p1 != (byte)0x00 && papdu.p1 != (byte)0x01)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // ��Կ��ʶֻ������0x06��0x07��0x08���μ�ʵ���ĵ�2
        if (papdu.p2 != (byte)0x06 && papdu.p2 != (byte)0x07 && papdu.p2 != (byte)0x08)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // ���Ȳ���Ϊ0Ҳ���ܳ���21
        if (papdu.lc == 0 || papdu.lc > 21)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // �ļ��ռ�����
        if (keyFile.recNum >= 3)
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        // �����Կ
        this.keyFile.addkey(papdu.p2, papdu.lc, papdu.data);
        return true;
    }
    // д��������ļ����μ�ʵ���ĵ�2
    private boolean write_bin() {
        // û����Կ�ļ�
        if (keyFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (papdu.cla != (byte)0x00)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.p1 != (byte)0x16 && papdu.p1 != (byte)0x17)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // д�볤�ȷ�0
        if (papdu.lc == 0)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // û�ж������ļ���p1==0x16��ʾӦ�û����ļ�cardFile��==0x17��ʾ�ֿ��˻����ļ�personFile
        if (papdu.p1 == (byte)0x16 && cardFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (papdu.p1 == (byte)0x17 && personFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // д��һ������������ļ�
        if (papdu.p1 == (byte)0x16)
            this.cardFile.write_binary(papdu.p2, papdu.lc, papdu.data);
        else if (papdu.p1 == (byte)0x17)
            this.personFile.write_binary(papdu.p2, papdu.lc, papdu.data);
        return true;
    }
    // ��ȡ�������ļ����μ�ʵ���ĵ�2
    private boolean read_bin() {
        // û����Կ�ļ�
        if (keyFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (papdu.cla != (byte)0x00)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.p1 != (byte)0x16 && papdu.p1 != (byte)0x17)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // û�ж������ļ���p1==0x16��ʾӦ�û����ļ�cardFile��==0x17��ʾ�ֿ��˻����ļ�personFile
        if (papdu.p1 == (byte)0x16 && cardFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (papdu.p1 == (byte)0x17 && personFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // ��ȡ��Ӧ�ļ�
        if (papdu.p1 == (byte)0x16)
            this.cardFile.read_binary(papdu.p2, papdu.le, papdu.data);
        else if (papdu.p1 == (byte)0x17)
            this.personFile.read_binary(papdu.p2, papdu.le, papdu.data);
        return true;
    }

    // Ȧ���ʼ��
    private boolean init_load() {
        short num, rc;
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x02)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if (papdu.lc != (short)0x0B)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (EPFile == null)
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        // ������Կ��ʶ��ȡ��Կ��¼��
        num = keyFile.findkey(papdu.data[0]);
        // �Ҳ�����Կ
        if (num == 0x00)
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        // 0�ɹ���2����
        rc = EPFile.init4load(num, papdu.data);
        if (rc == 2)
            ISOException.throwIt(condef.SW_LOAD_FULL);
        // ������bug
        papdu.le = (short)0x10;
        return true;
    }
    // Ȧ������
    private boolean load() {
        short rc;
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x00)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if (EPFile == null)
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        if (papdu.lc != (short)0x0B)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // 1MAC2У�����2���3δ�ҵ���Կ
        rc = EPFile.load(papdu.data);
        if (rc == 1)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        else if (rc == 2)
            ISOException.throwIt(condef.SW_LOAD_FULL);
        else if (rc == 3)
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        // ������bug
        papdu.le = (short)0x04;
        return true;
    }
    
    // ���ѳ�ʼ��
    private boolean init_purchase() {
        short num, rc;
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if (papdu.lc != (short)0x0B)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (EPFile == null)
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        // ������Կ��ʶ��ȡ��Կ��¼��
        num = keyFile.findkey(papdu.data[0]);
        // �Ҳ�����Կ
        if (num == 0x00)
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        // 0�ɹ���2����
        rc = EPFile.init4purchase(num, papdu.data);
        if (rc == 2)
            ISOException.throwIt(condef.SW_BALANCE_NOT_ENOUGH);
        // ������bug
        papdu.le = (short)0x0F;
        return true;
    }
    // ��������
    private boolean purchase() {
        short rc;
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x00)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if (EPFile == null)
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        if (papdu.lc != (short)0x0F)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // 1MAC2У�����2���3δ�ҵ���Կ
        rc = EPFile.purchase(papdu.data);
        if (rc == 1)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        else if (rc == 2)
            ISOException.throwIt(condef.SW_BALANCE_NOT_ENOUGH);
        else if (rc == 3)
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        // ������bug
        papdu.le = (short)0x08;
        return true;
    }
    
    // ����ѯ
    private boolean get_balance() {
        short result;
        byte[] balance = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // ��ȡ���
        result = EPFile.get_balance(balance);
        if (result == (short)4)
            Util.arrayCopyNonAtomic(balance, (short)0, papdu.data, (short)0, (short)4);
        // ������bug
        papdu.le = (short)0x04;
        return true;
    }
    
}