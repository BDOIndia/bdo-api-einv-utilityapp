
package com.bdoclient.apihelper.util;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.tomcat.util.codec.binary.Base64;
//import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AESEncryptionUtility {

	public static final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";
	public static final String AES_ALGORITHM = "AES";
	public static final int ENC_BITS = 256;
	public static final String CHARACTER_ENCODING = "UTF-8";

	private static Cipher encryptCipher;
	private static Cipher decryptCipher;
	private static KeyGenerator keygen;	
	
	public static final String EXCEPTION = "Exception :: {}";
	private static final Logger logger = LoggerFactory.getLogger(AESEncryptionUtility.class);

	private AESEncryptionUtility() {
		//private constructor to prevent instantiation of utility class and static members
	}
	static{
		try{
			encryptCipher = Cipher.getInstance(AES_TRANSFORMATION);
			decryptCipher = Cipher.getInstance(AES_TRANSFORMATION);
			keygen = KeyGenerator.getInstance(AES_ALGORITHM);
			keygen.init(ENC_BITS);
		}catch(NoSuchAlgorithmException | NoSuchPaddingException e) {			
			logger.error(EXCEPTION,e);
		}
	}

	/**
	 * This method is used to encode bytes[] to base64 string.
	 * 
	 * @param bytes
	 *            : Bytes to encode
	 * @return : Encoded Base64 String
	 */
	public static String encodeBase64String(byte[] bytes) {
		return new String(java.util.Base64.getEncoder().encode(bytes));
	}
	/**
	 * This method is used to decode the base64 encoded string to byte[]
	 * 
	 * @param stringData
	 *            : String to decode
	 * @return : decoded String
	 * @throws UnsupportedEncodingException
	 */
	public static byte[] decodeBase64StringTOByte(String stringData) {
		return java.util.Base64.getDecoder().decode(stringData.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * This method is used to encrypt the string which is passed to it as byte[] and return base64 encoded
	 * encrypted String
	 * @param plainText
	 *            : byte[]
	 * @param secret
	 *            : Key using for encrypt
	 * @return : base64 encoded of encrypted string.
	 * 
	 */

	public static String encryptEK(byte[] plainText, byte[] secret){
		try{

			SecretKeySpec sk = new SecretKeySpec(secret, AES_ALGORITHM);
			encryptCipher.init(Cipher.ENCRYPT_MODE, sk);
			return Base64.encodeBase64String(encryptCipher
					.doFinal(plainText));

		}catch(Exception e){
			logger.error(EXCEPTION,e);
			return "";
		}
	}


	/**
	 * This method is used to decrypt base64 encoded string using an AES 256 bit key.
	 * 
	 * @param plainText
	 *            : plain text to decrypt
	 * @param secret
	 *            : key to decrypt
	 * @return : Decrypted String
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] decrypt(String plainText, byte[] secret) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		SecretKeySpec sk = new SecretKeySpec(secret, AES_ALGORITHM);
		decryptCipher.init(Cipher.DECRYPT_MODE, sk);		
		return decryptCipher.doFinal(Base64.decodeBase64(plainText));
	}

	public static byte[] decryptCred(String plainText, byte[] secret)throws InvalidKeyException, IllegalBlockSizeException,BadPaddingException {
		SecretKeySpec sk = new SecretKeySpec(secret, AES_ALGORITHM);
		decryptCipher.init(Cipher.DECRYPT_MODE, sk);		
		return decryptCipher.doFinal(plainText.getBytes());
	}
	
	
}