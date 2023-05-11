package PQC_package;
import javacard.framework.*;
import javacardx.crypto.Cipher;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.AESKey;
import javacard.security.Signature;
import javacard.security.MessageDigest;
import javacardx.apdu.ExtendedLength;
import javacardx.framework.string.StringUtil;
import java.lang.*;

public class PQCTest extends Applet implements ExtendedLength {
	private byte[] cert;
  	private byte[] privKey;
	private byte[] pubKey;
	private short certLen;
	private short privKeyLen;
	private short pubKeyLen;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
  		new PQCTest();
  	}

	protected PQCTest() {
		cert=new byte[18000];
		privKey=new byte[1000];
		//pubKey=new byte[25000];
    		register();
	}

	public void sendLen(APDU apdu,short len) {
		short data=len;
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) 2);
		byte[] buffer=apdu.getBuffer();
		buffer[0]=(byte)(data>>8);
		buffer[1]=(byte)(data&0xFF);
		apdu.sendBytes((short)0,(short) 2);
	}

	public void sendIt(APDU apdu,byte[] arr,short len, byte P2) {
		byte ex=0;
		byte reason=0;
		byte progress=0;
		try {
			short portionSize=2048;
			short offset=(short)(P2*portionSize);
			short toSend=(short)(len-offset);
			if (toSend>portionSize) toSend=portionSize;
			progress=1;
	    		apdu.setOutgoing();
			progress=2;
	    		apdu.setOutgoingLength(toSend);
			progress=3;
	    		byte counter = 0;
	    		byte sendThisTime=0;
	    		while (toSend > 0) {
				progress=(byte)(4+2*counter);
	   			if (toSend>=32) sendThisTime=32; else sendThisTime=(byte) toSend;
	   			if (P2<0) {
	   				sendError(apdu,(byte)(offset>>8),(byte)(offset&0xFF),(byte)(((short)(32 * counter+offset))>>8),(byte)(((short)(32 * counter+offset))&0xFF),(byte)(toSend>>8),(byte)(toSend&0xFF));
	   				return;
	   			}
	    			apdu.sendBytesLong(arr, (short) (32 * counter+offset), (short) sendThisTime);
				progress=(byte)(4+2*counter+1);
	    			toSend = (short) (toSend - sendThisTime);
	    			counter = (byte) (counter + 1);
	    		}
		}
		catch (APDUException ae) {
			ex=6;
			reason=(byte)ae.getReason();
		}
		catch (SystemException se) {
			ex=5;
			reason=(byte)se.getReason();
		}
		catch(CryptoException ce) {
			short a=ce.getReason();
			ex=1;
			reason=(byte)a;
		}
		catch (ISOException e) {
			ex=2;
		}
		catch (SecurityException e) {
			SecurityException a=e;
			ex=3;
		}
		catch (Exception e) {
			ex=4;
		}
		finally {
			byte[] res=JCSystem.makeTransientByteArray((short)3,JCSystem.CLEAR_ON_RESET);
			res[0]=ex;
			res[1]=reason;
			res[2]=progress;
			apdu.setOutgoing();
	    		apdu.setOutgoingLength((short)3);
			apdu.sendBytesLong(res, (short)0, (short)3);
		}
	}

	private void sendError(APDU apdu,byte ex,byte reason,byte progress,byte a, byte b, byte c) {
		byte[] res=JCSystem.makeTransientByteArray((short)6,JCSystem.CLEAR_ON_RESET);
		res[0]=ex;
		res[1]=reason;
		res[2]=progress;
		res[3]=a;
		res[4]=b;
		res[5]=c;
		sendIt(apdu,res,(short)6,(byte)0);
	}
	
	public short setArray(APDU apdu,byte[] arr,short len) {
	    	byte ex=0;
		byte reason=0;
		byte progress=0;
	    	byte[] buffer=apdu.getBuffer();
	    	progress=1;
	    	short bytesRead = apdu.setIncomingAndReceive();
	    	progress=2;
		short dataOffset = apdu.getOffsetCdata();
		progress=3;
		byte count=0;
		try {
		    	while (bytesRead > 0) {
		    		progress=(byte)(10*count+4);
		    		Util.arrayCopyNonAtomic(buffer, dataOffset, arr, len, bytesRead);
		    		progress=(byte)(10*count+5);
		    		len+=bytesRead;
		    		progress=(byte)(10*count+6);
				//sendError(apdu,ex,reason,progress,(byte)dataOffset,(byte)len,(byte)bytesRead);
				//dataOffset+=bytesRead;
		    		bytesRead = apdu.receiveBytes(dataOffset);
		    		progress=(byte)(10*count+7);
		    		count++;
		    	}
		}
		catch (APDUException ae) {
			ex=6;
			short a=ae.getReason();
			reason=(byte)a;
			sendError(apdu,ex,reason,progress,(byte)dataOffset,(byte)len,(byte)bytesRead);
		}
		catch (Exception e) {
			ex=5;
			sendError(apdu,ex,reason,progress,(byte)dataOffset,(byte)len,(byte)bytesRead);
		}
	    	return len;
	}

	@Override
	public void process(APDU apdu) {
		byte[] buffer=apdu.getBuffer();
		byte[] arr=null;
		short len=0;
		byte P1=buffer[ISO7816.OFFSET_P1];
		byte P2=buffer[ISO7816.OFFSET_P2];
		switch (P1) {
			case 0x01:
				arr=cert;
				len=certLen;
				break;
			case 0x02:
				arr=privKey;
				len=privKeyLen;
				break;
			case 0x03:
				arr=pubKey;
				len=pubKeyLen;
				break;
		}
		switch (buffer[ISO7816.OFFSET_INS]) {
			case 0x20:
				len=setArray(apdu,arr,len);
				break;
			case 0x21:
				//for (short i=0;i<2048;i++) arr[i]=0;
				len=0;
				len=setArray(apdu,arr,len);
				break;
			case 0x23:
				//sendError(apdu,P2,P1,(byte)0,(byte)0,(byte)0,(byte)0);
				sendIt(apdu,arr,len,P2);
				break;
			case 0x24:
				sendLen(apdu,len);
				break;
		}
		if (P1==0x01) certLen=len;
		else if (P1==0x02) privKeyLen=len;
		else if (P1==0x03) pubKeyLen=len;
	}
}

