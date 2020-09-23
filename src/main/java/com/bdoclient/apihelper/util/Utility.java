package com.bdoclient.apihelper.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Blob;

import org.springframework.stereotype.Service;


@Service
public class Utility 
{	
	
	 public String readFile(String filePath) throws IOException
	    {
		 	String  content = new String(Files.readAllBytes(Paths.get(filePath)));
	        return content;
	    }
	 
	 
	 public String convertBlobToString(Blob requestBlob) throws Exception 
	 {
         String responseString = null;
         ByteArrayOutputStream baos = new ByteArrayOutputStream();
         byte[] buf = new byte[1024];
         try {
               
                 InputStream in = requestBlob.getBinaryStream();
                 Integer n = 0;
                 while ((n=in.read(buf))>=0)
                 {
                         baos.write(buf, 0, n);
                 }
                 in.close();
                 byte[] bytes = baos.toByteArray();
                 responseString = new String(bytes);
         } catch (Exception e) {                                
                 throw e;
         }

         return responseString;
 }
	 
	 public boolean moveFile(String oldFile,String newFile) throws IOException 
	 {
			boolean status=false;
			 Path temp = Files.move
				        (Paths.get(oldFile), 
				        Paths.get(newFile));
			 if(temp!=null) {
				 status= true;
			 }
			 return status;
	}
	 public void createDir(String batchedPath) 
	 {
		 File file = new File(batchedPath);
		 if(!file.exists()) {
			 file.mkdirs();
		 }
			 
	 }
	 
	 public File renameFile(String file, String newFile){
	     	File oldfile =new File(file);
	        File newfile =new File(newFile);

	        if(oldfile.renameTo(newfile))
	        {
	            return newfile;
	        }else
	        {
	            return null;
	        }
	 }
	 

}
