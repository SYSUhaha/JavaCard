// Q?
package purse;

public class condef {
    // INS Byte
    final static byte INS_CREATE_FILE        = (byte)0xE0;    // ???????????
    final static byte INS_WRITE_KEY          = (byte)0xD4;    // ��?????????
    final static byte INS_WRITE_BIN          = (byte)0xD6;    // ��??????????????
    final static byte INS_READ_BIN           = (byte)0xB0;    // ????????????????
    final static byte INS_NIIT_TRANS         = (byte)0x50;    // ??????????????????
    final static byte INS_LOAD               = (byte)0x52;    // ???????
    final static byte INS_PURCHASE           = (byte)0x54;    // ????????
	final static byte INS_GET_BALANCE        = (byte)0x5C;    // ??????????
	// INS Byte for Test
	final static byte INS_GET_SESPK          = (byte)0x60;    // ??????????
	final static byte INS_GET_MAC            = (byte)0x62;    // ????MAC??TAC
    // File Type Byte
    final static byte KEY_FILE               = (byte)0x3F;    // ???????????????
    final static byte CARD_FILE              = (byte)0x38;    // ??????????????????
    final static byte PERSON_FILE            = (byte)0x39;    // ????????????????????
    final static byte EP_FILE                = (byte)0x2F;    // ??????????
    // SW
    final static short SW_LOAD_FULL          = (short)0x9501; // ??��??
    final static short SW_BALANCE_NOT_ENOUGH = (short)0x9401; // ?????	
}
