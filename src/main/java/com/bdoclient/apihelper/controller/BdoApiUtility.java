package com.bdoclient.apihelper.controller;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.bdoclient.apihelper.util.AESEncryptionUtility;
import com.bdoclient.apihelper.util.RSAEncryptionUtility;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import io.swagger.annotations.ApiOperation;

@RestController
public class BdoApiUtility {

	@Value( "${bdo.public.key.path}" )
	private String bdoPubKeyPath;
	
	@Value( "${nic.public.key.path}" )
	private String nicPubKeyPath;
	
	@PostMapping("/encryptWithBDOkey")
    @ApiOperation("This API will encrypt BDO password using BDO App key {ecryptData}")
	public String encryptWithBDOPubKey(@RequestBody String ecryptData) throws Exception{
		PublicKey publicKey = RSAEncryptionUtility.getPublicKey(bdoPubKeyPath);
		String encText = new RSAEncryptionUtility().encryptTextWithPublicKey(ecryptData.trim(), publicKey);
		return encText;
	}
	
	@GetMapping("/getappkey")
    @ApiOperation("This API will encrypt BDO password using BDO App key")
	public String getAppKey() throws Exception{
		String appKey = RandomStringUtils.randomAlphanumeric(32);
		System.out.println("New AppKey : " + appKey + " on :" + LocalDateTime.now());
		return appKey;
	}
	
	@PostMapping("/encryptWithNICkey")
    @ApiOperation("This API will encrypt  password using NIC public key {ecryptData}")
	public String encryptWithNICPubKey(@RequestBody String ecryptData) throws Exception{
		String strPublicKeyPath = nicPubKeyPath;
		PublicKey publicKey = null;
		String encryptedPassword = null;
		try {
			RSAEncryptionUtility rsaEncUtil = new RSAEncryptionUtility();
			publicKey = rsaEncUtil.getPublic(strPublicKeyPath);
			encryptedPassword = rsaEncUtil.encryptTextWithPublicKey(ecryptData.trim(), publicKey);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encryptedPassword;
	}
	
	@PostMapping("/decryptsek")
    @ApiOperation("This API will decrypt sek{appkey and  sek}")
	public String decryptSEK(@RequestBody Map<String,String> mapMode) throws Exception{
		byte[] appKeyBytes = mapMode.get("appkey").getBytes(StandardCharsets.UTF_8);
		byte[] decryptedTextBytes = AESEncryptionUtility.decrypt(mapMode.get("sek"), appKeyBytes);

		return Base64.encodeBase64String(decryptedTextBytes);
	}
	
	@PostMapping("/encryptPayload")
    @ApiOperation("This API will encrypt payload {payload} parameter =decryptedSek")
	public String encryptPayload(@RequestBody String payload,@RequestParam String decryptedSek) throws Exception{
		
		byte[] sekByte = Base64.decodeBase64(decryptedSek.trim());
		
		Key aesKey = new SecretKeySpec(sekByte, "AES");
		try {

			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, aesKey);
			byte[] encryptedjsonbytes = cipher.doFinal(payload.getBytes());
			String encryptedJson = Base64.encodeBase64String(encryptedjsonbytes);
			return encryptedJson;
		} catch (Exception e) {
			e.printStackTrace();
			return "Exception " + e;
		}
	}
	
	@PostMapping("/decryptResponse")
    @ApiOperation("This API will decrypt response data {encryptedResponseData} and parameter = decryptedSek")
	public String decryptResponse(@RequestBody String encryptedResponseData,@RequestParam String decryptedSek) throws Exception{
		byte[] encKeyBytes = Base64.decodeBase64(decryptedSek.trim());
		byte[] decryptedTextBytes = AESEncryptionUtility.decrypt(encryptedResponseData, encKeyBytes);

		return new String(decryptedTextBytes);

	}
	
}
