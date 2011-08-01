package jm.oauth.messagesigner

import java.net.URLEncoder
import org.apache.commons.codec.digest.DigestUtils //nicer implementation to work with than java.security.MessageDigest
import org.apache.commons.codec.binary.Hex
import org.apache.commons.codec.binary.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.collection.immutable.SortedMap

class HmacSha1 extends jm.oauth.MessageSigner{
  
	//May compact the url, method, and params to a single object
	def createSignature(key: String, token: String, method: String, url: String, requestParams: Map[String, String]): String = {
	    //First create a SortedMap which is sorted on the key from our Map
		//and then feeds that into map() to combine key and value, then into reduce to join each k,v pair with an &
		val sorted = SortedMap(requestParams.toList:_*)
		val sigString = method.toUpperCase() + "&" + URLEncoder.encode(url) + "&" + 
				URLEncoder.encode(sorted.map(p => p._1 + "=" + p._2).reduceLeft{(joined,p) => joined + "&" + p})
  
		return new String(Base64.encodeBase64(generateSHA1Hash(sigString, key, token).getBytes()))
	}
	
	def generateSHA1Hash(value: String, key: String, token: String): String = {
	  
	  //When token is null it gets cast to the string "null" if it is just concatenated it in here
	  val keyString = URLEncoder.encode(key) + "&" + (token match {
	    case x if x != null => token
	    case x => ""
	  })
	  
	  val keyBytes = keyString.getBytes();           
	  val signingKey = new SecretKeySpec(keyBytes, "HmacSHA1")
	  val mac = Mac.getInstance("HmacSHA1");
	  mac.init(signingKey);
	  val rawHmac = mac.doFinal(value.getBytes());
	  return new String(rawHmac)
    //This is from an example, but it never worked
    //val hexBytes = new Hex().encode(rawHmac)
    //return new String(hexBytes, "UTF-8");
  }
}