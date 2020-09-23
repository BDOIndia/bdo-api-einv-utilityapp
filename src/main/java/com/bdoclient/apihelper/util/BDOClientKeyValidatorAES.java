package com.bdoclient.apihelper.util;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

//import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Component;


import lombok.extern.slf4j.Slf4j;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

@Slf4j
@Component
public class BDOClientKeyValidatorAES 
{
	private Cipher cipher;

	public static final String UTF8="UTF-8";
	
	public BDOClientKeyValidatorAES() throws NoSuchAlgorithmException, NoSuchPaddingException{
		this.cipher = Cipher.getInstance("RSA");
	}

	public PrivateKey getPrivate(String filename) throws Exception 
	{
		try{
			byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);
			}catch(Exception e){
				throw new Exception("Exception Occrred in getPrivate() in  GSPBDOClientKeyValidatorAES.class due to :" + e.toString(),e);
			}
		
	}
	
	public PrivateKey getPrivateOpenSSL(String filename) throws Exception 
	{
		try{
			byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);
		}catch(Exception e)
		{
			throw new Exception("Exception Occrred in getPrivateOpenSSL() in  GSPBDOClientKeyValidatorAES.class due to :" + e.toString(),e);
		}
	}
	

	public PublicKey getPublic(String filename) throws Exception 
	{
		try{
			byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
			X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(spec);
		}catch(Exception e){
			throw new Exception("Exception Occrred in getPublic() in  GSPBDOClientKeyValidatorAES.class due to :" + e.toString(),e);
		}
	}
	
	public void encryptFile(byte[] input, File output, PrivateKey key) throws GeneralSecurityException,Exception{
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		writeToFile(output, this.cipher.doFinal(input));
    }
	
	public void decryptFile(byte[] input, File output, PublicKey key) throws  GeneralSecurityException,Exception {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		writeToFile(output, this.cipher.doFinal(input));
    }
	
	private void writeToFile(File output, byte[] toWrite) throws Exception 
	{
		try(FileOutputStream fos= new FileOutputStream(output))
		{
			fos.write(toWrite);
			fos.flush();			
		}catch(Exception e){
			log.error("Exception Occurred in writeToFile() inside  GSPBDOClientKeyValidatorAES.class");
			throw new Exception("Exception Occrred in writeToFile() in  GSPBDOClientKeyValidatorAES.class due to :" + e.toString(),e);
		}
	}
	
	public String encryptTextWithPrivateKey(String msg, PrivateKey key) throws  UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException{
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(cipher.doFinal(msg.getBytes(UTF8)));
	}
	
	public String decryptTextWithPublicKey(String msg, PublicKey key) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.decodeBase64(msg)), UTF8);
	}
	
	public String encryptTextWithPublicKey(String msg, PublicKey key) throws  UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException{
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(cipher.doFinal(msg.getBytes(UTF8)));
	}
	
	public String decryptTextWithPrivateKey(String msg, PrivateKey key) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.decodeBase64(msg)), UTF8);
	}

	
	public static String getKey(String filename) throws Exception, IOException 
	{
	    String strKeyPEM = "";
	    try(BufferedReader br= new BufferedReader(new FileReader(filename)))
	    {
	    	String line;
	    	while ((line = br.readLine()) != null) {
	        strKeyPEM += line + "\n";
	    }
	    }catch(Exception e)
	    {
	    	log.error("Exception Occurred inside getKey() of GSPBDOClientKeyValidatorAES.class ");
	    	throw new Exception ("Exception Occurred inside getKey() of GSPBDOClientKeyValidatorAES.class ");
	    }
	    return strKeyPEM;
	}
	public static PrivateKey getPrivateKey(String filename) throws Exception {
	    try{String privateKeyPEM = getKey(filename);
	    return getPrivateKeyFromString(privateKeyPEM);
	    }catch(Exception e)
	    {
	    	throw new Exception("Ëxception Occurred in getPrivateKey()  in GSPBDOClientKeyValidatorAES.class due to " + e.toString());
	    }
	}

	public static PrivateKey getPrivateKeyFromString(String key) throws IOException, GeneralSecurityException {
	    String privateKeyPEM = key;
    
	    final String PEM_PRIVATE_START = "-----BEGIN PRIVATE KEY-----";
	    final String PEM_PRIVATE_END = "-----END PRIVATE KEY-----";

	    final String PEM_RSA_PRIVATE_START = "-----BEGIN RSA PRIVATE KEY-----";
	    final String PEM_RSA_PRIVATE_END = "-----END RSA PRIVATE KEY-----";


	    String privateKeyPem = privateKeyPEM;

	    if (privateKeyPem.indexOf(PEM_PRIVATE_START) != -1) { 
	        privateKeyPem = privateKeyPem.replace(PEM_PRIVATE_START, "").replace(PEM_PRIVATE_END, "");
	        privateKeyPem = privateKeyPem.replaceAll("\\s", "");

	        byte[] pkcs8EncodedKey = java.util.Base64.getDecoder().decode(privateKeyPem);

	        KeyFactory factory = KeyFactory.getInstance("RSA");
	        return factory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedKey));

	    } else if (privateKeyPem.indexOf(PEM_RSA_PRIVATE_START) != -1) { 
	        privateKeyPem = privateKeyPem.replace(PEM_RSA_PRIVATE_START, "").replace(PEM_RSA_PRIVATE_END, "");
	        privateKeyPem = privateKeyPem.replaceAll("\\s", "");

	        DerInputStream derReader = new DerInputStream(java.util.Base64.getDecoder().decode(privateKeyPem));

	        DerValue[] seq = derReader.getSequence(0);

	        if (seq.length < 9) {
	            throw new GeneralSecurityException("Could not parse a PKCS1 private key.");
	        }

	        BigInteger modulus = seq[1].getBigInteger();
	        BigInteger publicExp = seq[2].getBigInteger();
	        BigInteger privateExp = seq[3].getBigInteger();
	        BigInteger prime1 = seq[4].getBigInteger();
	        BigInteger prime2 = seq[5].getBigInteger();
	        BigInteger exp1 = seq[6].getBigInteger();
	        BigInteger exp2 = seq[7].getBigInteger();
	        BigInteger crtCoef = seq[8].getBigInteger();

	        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);

	        KeyFactory factory = KeyFactory.getInstance("RSA");

	        return factory.generatePrivate(keySpec);
	    }
		
	    return null;
	    
	}
	    



	public static PublicKey getPublicKey(String filename) throws Exception 
	{
	  try { String publicKeyPEM = getKey(filename);
	    return getPublicKeyFromString(publicKeyPEM);
	  }catch(Exception e)
	  {
		  throw new Exception("Exception Occurred in getPublicKey() in GSPBDOClientKeyValidatorAES.class due to :" + e.toString());
	  }
	}

	public static PublicKey getPublicKeyFromString(String key) throws   GeneralSecurityException {
	    String publicKeyPEM = key;
	    publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "");
	    publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
	    byte[] encoded = Base64.decodeBase64(publicKeyPEM);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return  kf.generatePublic(new X509EncodedKeySpec(encoded));
	}
	


}
