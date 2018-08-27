package purse;

// import Purse;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Purse extends Applet {
    // 实验内容1
    // 文件系统
    // APDU
    private Papdu papdu;
    // 密钥文件
    private KeyFile keyFile;
    // 应用基本文件
    private BinaryFile cardFile;
    // 持卡人基本文件
    private BinaryFile personFile;
    // 电子钱包文件
    private EPFile EPFile;
    // 注册
    public Purse(byte[] bArray, short bOffset, byte bLength) {
        papdu = new Papdu();
        byte aidLen = bArray[bOffset];
        if (aidLen == (byte)0x00)
            register();
        else
            register(bArray, (short)(bOffset+1), aidLen);
    }
    // 安装
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Purse(bArray, bOffset, bLength);
    }

    
    // 实验内容2
    // 执行
    public void process(APDU apdu) {
        if (selectingApplet())  return;
        // 取APDU缓冲区数组引用并将之赋值给新建数组
        byte[] buf = apdu.getBuffer();
        // 接收APDU中数据段并返回Data段的长度
        short lc = apdu.setIncomingAndReceive();
        // 取APDU缓冲区中的数据放到变量papdu中
        papdu.cla = buf[ISO7816.OFFSET_CLA];
        papdu.ins = buf[ISO7816.OFFSET_INS];
        papdu.p1 = buf[ISO7816.OFFSET_P1];
        papdu.p2 = buf[ISO7816.OFFSET_P2];
        // 判断APDU是否包含数据段
        // 包含: 获取数据长度, 赋值给le
        if (papdu.APDUContainData()) {
            papdu.lc = buf[ISO7816.OFFSET_LC];
            Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, papdu.data, (short)0, lc);
            if (ISO7816.OFFSET_CDATA+lc>=buf.length) papdu.le=0;
            else papdu.le = buf[ISO7816.OFFSET_CDATA+lc];
        }
        // 不包含: 不需要LC和Data，则获取缓冲区原本的LC部分实际上是LE部分
        else {
            papdu.le = buf[ISO7816.OFFSET_LC];
            papdu.lc = 0;
        }
        // 判断是否需要返回数据，并设置APDU缓冲区
        boolean rc = handleEvent();
        if (rc && papdu.le!=(byte)0) {
            Util.arrayCopyNonAtomic(papdu.data, (short)0, buf, ISO7816.OFFSET_CDATA, (short)papdu.data.length);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, papdu.le);//0,data.length
        }
    }
    // 分析&处理命令
    private boolean handleEvent() {
        // 根据INS进行分支，后续无需再对INS进行判断
        switch (papdu.ins) {
            // 文件建立
            case condef.INS_CREATE_FILE:
                return create_file();
            // 写入密钥
            case condef.INS_WRITE_KEY:
                return write_key();
            // 写入二进制文件
            case condef.INS_WRITE_BIN:
                return write_bin();
            // 读入二进制文件
            case condef.INS_READ_BIN:
                return read_bin();
            // 初始化圈存与消费
            case condef.INS_NIIT_TRANS:
                // 初始化圈存
                if (papdu.p1 == (byte)0x00)
                    return init_load();
                // 初始化消费
                if (papdu.p1 == (byte)0x01)
                    return init_purchase();
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            // 圈存
            case condef.INS_LOAD:
                return load();
            // 消费
            case condef.INS_PURCHASE:
                return purchase();
            // 查询余额
            case condef.INS_GET_BALANCE:
                return get_balance();
            // 测试过程密钥算法
            case condef.INS_GET_SESPK:
            	return test_processkey();
            // 测试MAC算法
            case condef.INS_GET_MAC:
            	return test_mackey();
        }    
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return false;
    }
    //测试
    /*
     * 测试过程密钥
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
     * 测试MAC密钥
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
    // 文件建立
    private boolean create_file() {
        // 判断取值参见实验文档2，根据Data域Byte1确定文件类型
        switch (papdu.data[0]) {
            // 电子钱包文件
            case condef.EP_FILE:
                return ep_file();
            // 密钥文件，应当优先创建
            case condef.KEY_FILE:
                return key_file();
            // 应用基本文件
            case condef.CARD_FILE:
                return card_file();
            // 持卡人基本文件
            case condef.PERSON_FILE:
                return person_file();
            default: 
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        return true;
    }
    // 建立电子钱包文件，参见实验文档2
    private boolean ep_file() {
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x18)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // 重复创建
        if (EPFile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // 没有密钥文件
        if (keyFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        this.EPFile = new EPFile(keyFile);
        return true;
    }
    // 建立密钥文件，参见实验文档2
    private boolean key_file() {
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x00)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // 重复创建
        if (keyFile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        this.keyFile = new KeyFile();
        return true;
    }
    // 建立应用基本文件，参见实验文档2
    private boolean card_file() {
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x16)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // 重复创建
        if (cardFile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // 没有密钥文件
        if (keyFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // 传入要写入的内容
        this.cardFile = new BinaryFile(papdu.data);
        return true;
    }
    // 建立持卡人信息文件，参见实验文档2
    private boolean person_file() {
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x17)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // 重复创建
        if (personFile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // 没有密钥文件
        if (keyFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // 传入要写入的内容
        this.personFile = new BinaryFile(papdu.data);
        return true;
    }
    // 写入密钥，参见实验文档2
    private boolean write_key() {
        // 没有密钥文件
        if (keyFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        // ==0x00新增，==0x01修改
        if (papdu.p1 != (byte)0x00 && papdu.p1 != (byte)0x01)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // 密钥标识只有三种0x06，0x07，0x08，参见实验文档2
        if (papdu.p2 != (byte)0x06 && papdu.p2 != (byte)0x07 && papdu.p2 != (byte)0x08)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // 长度不能为0也不能超过21
        if (papdu.lc == 0 || papdu.lc > 21)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // 文件空间已满
        if (keyFile.recNum >= 3)
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        // 添加密钥
        this.keyFile.addkey(papdu.p2, papdu.lc, papdu.data);
        return true;
    }
    // 写入二进制文件，参见实验文档2
    private boolean write_bin() {
        // 没有密钥文件
        if (keyFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (papdu.cla != (byte)0x00)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.p1 != (byte)0x16 && papdu.p1 != (byte)0x17)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // 写入长度非0
        if (papdu.lc == 0)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // 没有二进制文件，p1==0x16表示应用基本文件cardFile，==0x17表示持卡人基本文件personFile
        if (papdu.p1 == (byte)0x16 && cardFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (papdu.p1 == (byte)0x17 && personFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // 写入一条二进制命令到文件
        if (papdu.p1 == (byte)0x16)
            this.cardFile.write_binary(papdu.p2, papdu.lc, papdu.data);
        else if (papdu.p1 == (byte)0x17)
            this.personFile.write_binary(papdu.p2, papdu.lc, papdu.data);
        return true;
    }
    // 读取二进制文件，参见实验文档2
    private boolean read_bin() {
        // 没有密钥文件
        if (keyFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (papdu.cla != (byte)0x00)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.p1 != (byte)0x16 && papdu.p1 != (byte)0x17)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // 没有二进制文件，p1==0x16表示应用基本文件cardFile，==0x17表示持卡人基本文件personFile
        if (papdu.p1 == (byte)0x16 && cardFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (papdu.p1 == (byte)0x17 && personFile == null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // 读取相应文件
        if (papdu.p1 == (byte)0x16)
            this.cardFile.read_binary(papdu.p2, papdu.le, papdu.data);
        else if (papdu.p1 == (byte)0x17)
            this.personFile.read_binary(papdu.p2, papdu.le, papdu.data);
        return true;
    }

    // 圈存初始化
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
        // 根据密钥标识获取密钥记录号
        num = keyFile.findkey(papdu.data[0]);
        // 找不到密钥
        if (num == 0x00)
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        // 0成功，2超额
        rc = EPFile.init4load(num, papdu.data);
        if (rc == 2)
            ISOException.throwIt(condef.SW_LOAD_FULL);
        // 可能有bug
        papdu.le = (short)0x10;
        return true;
    }
    // 圈存命令
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
        // 1MAC2校验错误，2超额，3未找到密钥
        rc = EPFile.load(papdu.data);
        if (rc == 1)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        else if (rc == 2)
            ISOException.throwIt(condef.SW_LOAD_FULL);
        else if (rc == 3)
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        // 可能有bug
        papdu.le = (short)0x04;
        return true;
    }
    
    // 消费初始化
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
        // 根据密钥标识获取密钥记录号
        num = keyFile.findkey(papdu.data[0]);
        // 找不到密钥
        if (num == 0x00)
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        // 0成功，2超额
        rc = EPFile.init4purchase(num, papdu.data);
        if (rc == 2)
            ISOException.throwIt(condef.SW_BALANCE_NOT_ENOUGH);
        // 可能有bug
        papdu.le = (short)0x0F;
        return true;
    }
    // 消费命令
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
        // 1MAC2校验错误，2超额，3未找到密钥
        rc = EPFile.purchase(papdu.data);
        if (rc == 1)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        else if (rc == 2)
            ISOException.throwIt(condef.SW_BALANCE_NOT_ENOUGH);
        else if (rc == 3)
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        // 可能有bug
        papdu.le = (short)0x08;
        return true;
    }
    
    // 余额查询
    private boolean get_balance() {
        short result;
        byte[] balance = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
        if (papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if (papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        // 获取余额
        result = EPFile.get_balance(balance);
        if (result == (short)4)
            Util.arrayCopyNonAtomic(balance, (short)0, papdu.data, (short)0, (short)4);
        // 可能有bug
        papdu.le = (short)0x04;
        return true;
    }
    
}