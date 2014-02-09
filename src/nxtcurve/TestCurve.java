package nxtcurve;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import nxt.crypto.Curve25519;
import nxt.crypto.Curve25519bad;

public class TestCurve {
	public static final String password = "It was a bright cold day in April, and the clocks were striking thirteen";
	public static final int Number_Of_Tests = 1000;
	public static final int Number_Of_Groups = 100;
	
	public static MessageDigest getMessageDigest(String paramString)
	{
		try
		{
			return MessageDigest.getInstance(paramString);
		}
		catch (NoSuchAlgorithmException localNoSuchAlgorithmException)
		{
			System.exit(1);
		}
		return null;
	}

	public static MessageDigest sha256()
	{
		return getMessageDigest("SHA-256");
	}
	
	public static byte[] signBad(byte[] paramArrayOfByte, String paramString)
	{
		try
		{
			byte[] arrayOfByte1 = new byte[32];
			byte[] arrayOfByte2 = new byte[32];
			MessageDigest localMessageDigest = sha256();
			Curve25519.keygen(arrayOfByte1, arrayOfByte2, localMessageDigest.digest(paramString.getBytes("UTF-8")));

			byte[] arrayOfByte3 = localMessageDigest.digest(paramArrayOfByte);

			localMessageDigest.update(arrayOfByte3);
			byte[] arrayOfByte4 = localMessageDigest.digest(arrayOfByte2);

			byte[] arrayOfByte5 = new byte[32];
			Curve25519.keygen(arrayOfByte5, null, arrayOfByte4);

			localMessageDigest.update(arrayOfByte3);
			byte[] arrayOfByte6 = localMessageDigest.digest(arrayOfByte5);

			byte[] arrayOfByte7 = new byte[32];
			Curve25519bad.sign(arrayOfByte7, arrayOfByte6, arrayOfByte4, arrayOfByte2);

			byte[] arrayOfByte8 = new byte[64];
			System.arraycopy(arrayOfByte7, 0, arrayOfByte8, 0, 32);
			System.arraycopy(arrayOfByte6, 0, arrayOfByte8, 32, 32);

			return arrayOfByte8;
		}
		catch (RuntimeException|UnsupportedEncodingException localRuntimeException)
		{
			System.err.println("Error in signing message");
		}
		return null;
	}

	public static byte[] signGood(byte[] paramArrayOfByte, String paramString)
	{
		try
		{
			byte[] arrayOfByte1 = new byte[32];
			byte[] arrayOfByte2 = new byte[32];
			MessageDigest localMessageDigest = sha256();
			Curve25519.keygen(arrayOfByte1, arrayOfByte2, localMessageDigest.digest(paramString.getBytes("UTF-8")));

			byte[] arrayOfByte3 = localMessageDigest.digest(paramArrayOfByte);

			localMessageDigest.update(arrayOfByte3);
			byte[] arrayOfByte4 = localMessageDigest.digest(arrayOfByte2);

			byte[] arrayOfByte5 = new byte[32];
			Curve25519.keygen(arrayOfByte5, null, arrayOfByte4);

			localMessageDigest.update(arrayOfByte3);
			byte[] arrayOfByte6 = localMessageDigest.digest(arrayOfByte5);

			byte[] arrayOfByte7 = new byte[32];
			Curve25519.sign(arrayOfByte7, arrayOfByte6, arrayOfByte4, arrayOfByte2);

			byte[] arrayOfByte8 = new byte[64];
			System.arraycopy(arrayOfByte7, 0, arrayOfByte8, 0, 32);
			System.arraycopy(arrayOfByte6, 0, arrayOfByte8, 32, 32);

			return arrayOfByte8;
		}
		catch (RuntimeException|UnsupportedEncodingException localRuntimeException)
		{
			System.err.println("Error in signing message");
		}
		return null;
	}
	
	public static boolean verify(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3)
	{
		try
		{
			byte[] arrayOfByte1 = new byte[32];
			byte[] arrayOfByte2 = new byte[32];
			System.arraycopy(paramArrayOfByte1, 0, arrayOfByte2, 0, 32);
			byte[] arrayOfByte3 = new byte[32];
			System.arraycopy(paramArrayOfByte1, 32, arrayOfByte3, 0, 32);
			Curve25519.verify(arrayOfByte1, arrayOfByte2, arrayOfByte3, paramArrayOfByte3);

			MessageDigest localMessageDigest = sha256();
			byte[] arrayOfByte4 = localMessageDigest.digest(paramArrayOfByte2);
			localMessageDigest.update(arrayOfByte4);
			byte[] arrayOfByte5 = localMessageDigest.digest(arrayOfByte1);

			return Arrays.equals(arrayOfByte3, arrayOfByte5);
		}
		catch (RuntimeException localRuntimeException)
		{
			System.err.println("Error in Crypto verify");
		}
		return false;
	}
	public static void main(String[] args) {
		Random rng;
		byte[] data;
		
		if (args.length > 1) {
			rng = new Random(Long.parseLong(args[1]));
		} else {
			rng = new Random(666);
		}
		
		MessageDigest localMessageDigest = sha256();
		byte publicKey[] = new byte[64];
		try {
			Curve25519.keygen(publicKey, null, localMessageDigest.digest(password.getBytes("UTF-8")));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		for (int j=0; j<Number_Of_Groups; ++j)
		{
			int badCounter1 = 0;
			int badCounter2 = 0;
			data = new byte[224 + rng.nextInt(256)];
			
			for (int i=0; i<Number_Of_Tests; ++i) {
				rng.nextBytes(data);
				byte[] sig1 = TestCurve.signBad(data, password);
				byte[] sig2 = TestCurve.signGood(data, password);
				if (TestCurve.verify(sig1, data, publicKey) == false) {
					badCounter1++;
				}
				if (TestCurve.verify(sig2, data, publicKey) == false) {
					badCounter2++;
				}
			}
			
			System.out.println(String.format("      original failed: %d / %d ", badCounter1, Number_Of_Tests));
			System.out.println(String.format("BloodyRookie's failed: %d / %d ", badCounter2, Number_Of_Tests));
		}
	}
}
