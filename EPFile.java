// 电子钱包文件
package purse;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class EPFile {
    private KeyFile keyFile;
    
    // 内部数据元
    // 电子钱包余额
    private byte[] EP_balance;
    // 电子钱包脱机交易序号，消费相关
    private byte[] EP_offline;
    // 电子钱包联机交易序号，圈存相关
    private byte[] EP_online;
    
    // 密钥版本号
    byte keyID;
    // 算法标识
    byte algID;
    
    // 随机数生成
    private Randgenerator randGen;
    // 数据加解密方式实现
    private PenCipher penCipher;

    // 临时计算数据
    // 4字节临时计算数据
    private byte[] tmp1;           
    private byte[] tmp2;
    // 8字节临时计算数据
    private byte[] tmp3;
    private byte[] tmp4;
    // 32字节临时计算数据
    private byte[] tmp5;
    private byte[] tmp6;
    

    public EPFile(KeyFile keyFile) {
        // 初始化为0
        // 余额 4字节
        EP_balance = new byte[4];
        Util.arrayFillNonAtomic(EP_balance, (short)0, (short)4, (byte)0x00);
        // 脱机交易序号 2字节
        EP_offline = new byte[2];
        Util.arrayFillNonAtomic(EP_offline, (short)0, (short)2, (byte)0x00);
        // 联机交易序号 2字节
        EP_online = new byte[2];
        Util.arrayFillNonAtomic(EP_online, (short)0, (short)2, (byte)0x00);
        
        this.keyFile = keyFile;
        
        // 开辟空间
        tmp1 = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
        tmp2 = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
        tmp3 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
        tmp4 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
        tmp5 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        tmp6 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);

        // 实例化
        randGen = new Randgenerator();
        penCipher = new PenCipher();
    }
    

    // 增加电子钱包金额
    // data：增加的金额，flag：是否真的增加（可能只是圈存初始化）
    // 返回：圈存后余额是否超过最大限额
    public final short increase(byte[] data, boolean flag) {
        short i, t1, t2, lim;
        lim = (short)0;
        for (i=3; i>=0; i--) {
            // EP_balance[(short)i]与data[i]均为1字节，t1、t2是short类型2字节，补0xFF
            t1 = (short)(EP_balance[(short)i]&0xFF);
            t2 = (short)(data[i]&0xFF); 
            t1 = (short)(t1+t2+lim);
            // 真增加，修改余额
            if (flag)
                EP_balance[(short)i] = (byte)(t1%256);
            lim = (short)(t1/256);
        }
        // 非零表示超过最大限额
        return lim;
    }
    // 圈存初始化
    // num：密钥记录号，data：命令报文中的数据段
    // 返回：0执行成功，2超额
    public final short init4load(short num, byte[] data) {
        short len, rc;
        // 判断是否超额圈存
        // 参见实验4文档-圈存初始化-命令报文-Data段
        // 交易金额存入tmp2
        Util.arrayCopyNonAtomic(data, (short)1, tmp2, (short)0, (short)4);
        // 终端机编号存入tmp3
        Util.arrayCopyNonAtomic(data, (short)5, tmp3, (short)0, (short)6);
        // tmp2当前存放交易金额，判断是否超额
        rc = increase(tmp2, false);
        if (rc != (short)0)
            return (short)2;
        
        // 查找圈存密钥
        // len：密钥长度，num：密钥记录号，tmp6：存放密钥的缓冲区
        len = keyFile.readkey(num, tmp6);
        // 从密钥中获取密钥版本号和算法标识，密钥文件结构参见实验文档2
        keyID = tmp6[3];
        algID = tmp6[4];
        // 查找之前存入文件的圈存密钥值，存入tmp5
        Util.arrayCopyNonAtomic(tmp6, (short)5, tmp5, (short)0, len);
        // 生成过程密钥
        // 生成随机数放入tmp6，tmp[0][1][2][3]存放随机数
        randGen.GenerateSecureRnd();
        randGen.GetRndValue(tmp6, (short)0);
        // 联机交易序列号EP_online赋值给tmp6[4][5]
        Util.arrayCopyNonAtomic(EP_online, (short)0, tmp6, (short)4, (short)2);
        // 补全，作为生成过程密钥的输入数据，输入数据格式参见实验4文档-电子钱包功能设计-圈存-1-2
        tmp6[6] = (byte)0x80;
        tmp6[7] = (byte)0x00;
        // tmp5当前存放密钥，tmp6当前存放伪随机数+联机交易序列号EP_online+8000，生成过程密钥存入tmp4
        penCipher.gen_processkey(tmp5, tmp6, (short)0, (short)8, tmp4, (short)0); 
        // 生成MAC1
        // 电子钱包余额EP_balance放入tmp6[0][1][2][3]
        Util.arrayCopyNonAtomic(EP_balance, (short)0, tmp6, (short)0, (short)4);
        // 交易金额放入tmp6[4][5][6]][7]
        Util.arrayCopyNonAtomic(data, (short)1, tmp6, (short)4, (short)4);
        // 交易类型标识0x02放入tmp6[8]
        tmp6[8] = (byte)0x02;
        // 终端机编号放入tmp6[9][10][11][12][13][14]
        Util.arrayCopyNonAtomic(data, (short)5, tmp6, (short)9, (short)6);
        // 生成MAC1并存入tmp1
        // tmp4当前存放过程密钥，tmp6当前存放 当前电子钱包余额EP_balance+交易金额+交易类型标识0x02+终端机编号
        penCipher.gen_ac(tmp4, tmp6, (short)0x0F, tmp1);
        // IC卡返回响应数据
        // 响应数据域参见实验4文档-电子钱包的命令解析-圈存初始化-响应报文数据域
        // 电子钱包余额存入data[0][1][2][3]
        Util.arrayCopyNonAtomic(EP_balance, (short)0, data, (short)0, (short)4);
        // 电子钱包联机交易序号EP_online存入data[4][5]
        //ISOException.throwIt((byte)data.length);
        Util.arrayCopyNonAtomic(EP_online, (short)0, data,  (short)4, (short)2);
        //ISOException.throwIt((byte)data.length);
        // 密钥版本号存入data[6]
        data[6] = keyID;
        // 算法标识存入data[7]
        data[7] = algID;
        // 随机数存入data[8][9][10][11]
        //ISOException.throwIt((byte)data.length);
        //bug!!!!!
        randGen.GetRndValue(data, (short)8);
        // 将MAC1赋给data[12][13][14][15];
        Util.arrayCopyNonAtomic(tmp1, (short)0, data, (short)12, (short)4);
        return 0;
    }
    // 圈存
    // data：命令报文中的数据段
    // 返回：0圈存命令执行成功，1MAC2校验错误，2圈存超过最大限额，3密钥未找到
    public final short load(byte[] data) {
        short rc, len, num;
        
        // IC卡利用过程密钥生成MAC2，再跟终端传过来的MAC2验证，相同则MAC2有效
        // data是命令报文数据段，参见实验文档4-电子钱包功能设计-圈存-3
        // 用tmp6存放生成MAC2的输入数据，交易金额+交易标识+终端机编号+交易日期（主机）+交易时间（主机）
        // tmp2当前存放交易金额，放入tmp6[0][1][2][3]
        Util.arrayCopyNonAtomic(tmp2, (short)0, tmp6, (short)0, (short)4);       
        // 交易标识0x02放入tmp6[4]
        tmp6[4] = (byte)0x02;                                                       
        // tmp3当前存放终端机编号，存入tmp6[5][6][7][8][9][10]
        Util.arrayCopyNonAtomic(tmp3, (short)0, tmp6, (short)5, (short)6);       
        // 交易日期与时间存入tmp6[11][12][13][14][15][16][17]
        Util.arrayCopyNonAtomic(data, (short)0, tmp6, (short)11, (short)7);         
        // tmp6长度18，生成的MAC2放入tmp1
        penCipher.gen_ac(tmp4, tmp6, (short)18, tmp1);
        // 检验MAC2，错误返回1
        // arrayCompare(byte[] src, short srcOff, byte[] dest, short destOff, short length) 
        // data[7][8][9][10]是命令报文中的MAC2，tmp1存放这IC卡生成的MAC2
        if (Util.arrayCompare(data, (short)7, tmp1, (short)0, (short)4) != (byte)0x00)
            return (short)1;
        
        // 电子钱包金额增加
        rc = increase(tmp2, true);
        if(rc != (short)0)
            return (short)2;
        
        // 生成TAC，返回给终端
        // 用tmp6存放生成TAC的输入数据，电子钱包余额（交易后）+电子钱包联机交易序号（加１前）+交易金额+交易类型标识+终端机编号+交易日期（主机）+交易时间（主机）
        // 电子钱包余额EP_balance放入tmp6[0][1][2][3]
        Util.arrayCopyNonAtomic(EP_balance, (short)0, tmp6, (short)0, (short)4);
        // 联机交易序号EP_online放入tmp[4][5]
        Util.arrayCopyNonAtomic(EP_online, (short)0, tmp6, (short)4, (short)2);
        // tmp2当前存放交易金额，存入tmp6[6][7][8][9]
        Util.arrayCopyNonAtomic(tmp2, (short)0, tmp6, (short)6, (short)4);
        // 交易类型存入tmp6[10]
        tmp6[10] = (byte)0x02;
        // tmp3当前存放终端机编号，存入tmp6[11][12][13][14][15][16]
        Util.arrayCopyNonAtomic(tmp3, (short)0, tmp6, (short)11, (short)6);
        // 交易日期与时间存入tmp6[17][18][19][20][21][22][23]
        Util.arrayCopyNonAtomic(data, (short)0, tmp6, (short)17, (short)7);
        
        // 联机交易序号EP_online加1，放在这里是因为TAC需要的输入数据中，联机交易序号需要的是+1前的数据
        rc = Util.makeShort(EP_online[0], EP_online[1]);
        rc++;
        if (rc > (short)256)
            rc = (short)1;
        Util.setShort(EP_online, (short)0, rc);
        
        // 生成TAC
        // num：记录号，tmp5：密钥存入处，len：密钥长度
        // 0x34对应TAC密钥类型
        num = keyFile.findKeyByType((byte)0x34);
        len = keyFile.readkey(num, tmp5);
        // 长度为0，即不存在密钥
        if (len == 0)
            return (short)3;
        // 去掉前五位TAC密钥头部，得到的TAC密钥值放入tmp4中
        Util.arrayCopyNonAtomic(tmp5, (short)5, tmp4, (short)0, (short)8);
        // TAC密钥最左8个字节（tmp4）与最右8个字节（tmp5[13]...）异或，结果放入tmp5中，即为tmp5[13][14][15][16][17][18][19][20]
        penCipher.xor_8byte(tmp4, tmp5, (short)13);
        // tmp5[13][14][15][16][17][18][19][20]是生成TAC需要的密钥值，存入tmp中
        byte[] tmp = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(tmp5, (short)13, tmp, (short)0, (short)8);
        // 生成TAC，存入data
        penCipher.gen_ac(tmp, tmp6, (short)24, data);
        return (short)0;
    }
    

    // 减少电子钱包金额
    // data：减少的金额，flag：是否真的减少（可能只是消费初始化）
    // 返回：消费后是否超额
    public final short decrease(byte[] data, boolean flag) {
        short i, t1, t2, lim;
        lim = (short)0;
        for (i=3; i>=0; i--) {
            // EP_balance[(short)i]与data[i]均为1字节，t1、t2是short类型2字节，补0xFF
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
    // 消费初始化
    // num：密钥记录号，data：命令报文中的数据段
    // 返回：0执行成功，2超额
    public final short init4purchase(short num, byte[] data) {
        short len, rc;
        // 判断是否超额消费
        // 参见实验4文档-消费初始化-命令报文-Data段
        // 交易金额存入tmp2
        Util.arrayCopyNonAtomic(data, (short)1, tmp2, (short)0, (short)4);
        // 终端机编号存入tmp3
        Util.arrayCopyNonAtomic(data, (short)5, tmp3, (short)0, (short)6);
        // tmp2当前存放交易金额，判断是否超额
        rc = decrease(tmp2, false);
        if(rc != (short)0)
            return (short)2;
        
        // 查找消费密钥
        // len：密钥长度，num：密钥记录号，tmp6：存放密钥的缓冲区
        len = keyFile.readkey(num, tmp6);
        // 从密钥中获取密钥版本号和算法标识，密钥文件结构参见实验文档2
        
        keyID = tmp6[3];
        algID = tmp6[4];
        // 查找之前存入文件的消费密钥值，存入tmp5
       
        Util.arrayCopyNonAtomic(tmp6, (short)5, tmp5, (short)0, len);
        
        // 生成随机数，存入tmp6
        randGen.GenerateSecureRnd();
        randGen.GetRndValue(tmp6, (short)0);
        // 返回响应数据
        // 数据域参见实验4文档-电子钱包的命令解析-消费初始化-响应报文数据域
        // 电子钱包余额EP_balance存入data[0][1][2][3]
        Util.arrayCopyNonAtomic(EP_balance, (short)0, data, (short)0, (short)4);
        // 脱机交易序号EP_offline存入data[4][5]
        Util.arrayCopyNonAtomic(EP_offline, (short)0, data,  (short)4, (short)2);
        // 透支限额存入data[6][7][8]
        // arrayFillNonAtomic(byte[] bArray, short bOff, short bLen, byte bValue) 
        Util.arrayFillNonAtomic(data, (short)6, (short)3, (byte)0x00);
        // 密钥版本号存入data[9]
        data[9] = keyID;
        // 算法标识存入data[10]
        data[10] = algID;
        // 将随机数赋给data[11][12][13][14]
        randGen.GetRndValue(data, (short)11);
        return 0;
        
    }
    // 消费命令
    // data：命令报文中的数据段
    // 返回：0命令执行成功，1MAC校验错误，2消费超额，3未找到密钥
    public final short purchase(byte[] data) {
        short rc, len, num;

        // tmp5当前存放消费密钥值
        // tmp6当前存放随机数

        // 生成过程密钥
        // tmp6存放生成过程密钥的输入数据，伪随机数+电子钱包脱机交易序号+终端交易序号的最右两个字节
        // 脱机交易序列号EP_offline存入tmp6[4][5]
        Util.arrayCopyNonAtomic(EP_offline, (short)0, tmp6, (short)4, (short)2);
        // 终端交易序号后两字节存入tmp6[6][7]
        Util.arrayCopyNonAtomic(data, (short)2, tmp6, (short)6, (short)2);
        // 生成过程密钥，存入tmp4
        penCipher.gen_processkey(tmp5, tmp6, (short)0, (short)8, tmp4, (short)0);
        
        // IC卡利用过程密钥生成MAC1，再跟终端传过来的MAC1验证，相同则MAC1有效
        // 输入数据：交易金额||交易类型标识(0x06)||终端机编号||交易日期（主机）||交易时间（主机）
        // 交易金额存入tmp6[0][1][2][3]
        Util.arrayCopyNonAtomic(tmp2, (short)0, tmp6, (short)0, (short)4);
        // 交易标识存入tmp6[4]
        tmp6[4] = (byte)0x07;
        // 终端机编号存入tmp6[5][6][7][8][9][10]
        Util.arrayCopyNonAtomic(tmp3, (short)0, tmp6, (short)5, (short)6);
        // 交易日期和时间存入tmp6[11][12][13][14][15][16][17]
        Util.arrayCopyNonAtomic(data, (short)4, tmp6, (short)11, (short)7);
        // tmp4当前存放过程密钥，tmp6当前存放输入数据，生成MAC1存入tmp1
        penCipher.gen_ac(tmp4, tmp6, (short)18, tmp1);
        
        // 检验MAC1，不相同返回1
        // data[11][12][13][14]是命令报文中的MAC1
        if (Util.arrayCompare(data, (short)11, tmp1, (short)0, (short)4) != (byte)0x00)
            return (short)1;
        
        // 脱机交易序号加1
        rc = Util.makeShort(EP_offline[0], EP_offline[1]);
        rc++;
        if (rc > (short)256)
            rc = (short)1;
        Util.setShort(EP_offline, (short)0, rc);
        
        // 电子钱包金额减少
        rc = decrease(tmp2, true);
        if(rc != (short)0)
            return (short)2;
    
        // MAC2生成
        // 交易金额作为数据输入tmp6[0]~[3]
        Util.arrayCopyNonAtomic(tmp2, (short)0, tmp6, (short)0, (short)4);           
        // tmp4为过程密钥，tmp6为输入数据，得到MAC2存入tmp1，会修改数据tmp6，后续需要使用tmp6
        penCipher.gen_ac(tmp4, tmp6, (short)4, tmp1);
        
        // 生成TAC，返回给终端
        // tmp6存放生成TAC的输入数据，交易金额+交易类型标识+终端机编号+终端交易序号+交易日期（主机）+交易时间（主机）
        // 交易金额存入tmp6[0][1][2][3]
        Util.arrayCopyNonAtomic(tmp2, (short)0, tmp6, (short)0, (short)4);
        // 交易类型标识存入tmp6[4]
        tmp6[4] = (byte)0x06;
        // 终端机编号存入tmp6[5][6][7][8][9][10]
        Util.arrayCopyNonAtomic(tmp3, (short)0, tmp6, (short)5, (short)6);
        // 终端交易序号存入tmp6[11][12][13][14]
        Util.arrayCopyNonAtomic(data, (short)0, tmp6, (short)11, (short)4);
        // 交易日期与时间存入tmp6[15][16][17][18][19][20][21]
        Util.arrayCopyNonAtomic(data, (short)4, tmp6, (short)15, (short)7);
        // 生成TAC
        // num：记录号，tmp5：密钥存入处，len：密钥长度
        // 0x34对应TAC密钥类型
        num = keyFile.findKeyByType((byte)0x34);
        len = keyFile.readkey(num, tmp5);
        // 长度为0，即不存在密钥
        if (len == 0)
            return (short)3;
        // 去掉前五位TAC密钥头部，得到的TAC密钥值放入tmp4中
        Util.arrayCopyNonAtomic(tmp5, (short)5, tmp4, (short)0, (short)8);
        // TAC密钥最左8个字节（tmp4）与最右8个字节（tmp5[13]...）异或，结果放入tmp5中，即为tmp5[13][14][15][16][17][18][19][20]
        penCipher.xor_8byte(tmp4, tmp5, (short)13);
        // tmp5[13][14][15][16][17][18][19][20]是生成TAC需要的密钥值，放入tmp中
        byte[] tmp = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(tmp5, (short)13, tmp, (short)0, (short)8);
        // MAC2存入data[4][5][6][7]
        Util.arrayCopyNonAtomic(tmp1, (short)0, data, (short)4, (short)4);
        // 生成TAC，存入data[0][1][2][3]
        // tmp为所需密钥值，tmp6为输入数据，会被修改
        penCipher.gen_ac(tmp, tmp6, (short)22, data);
        return 0;
    }


    // 获取电子钱包余额
    // data：电子钱包余额的缓冲区
    public final short get_balance(byte[] data) {
        return Util.arrayCopyNonAtomic(EP_balance, (short)0, data, (short)0, (short)4);
    }
}