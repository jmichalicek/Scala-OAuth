package jm.oauth.messagesigner

import jm.oauth.MessageSigner
//import java.net.URLEncoder
import jm.oauth.URLEncoder
import org.apache.commons.codec.digest.DigestUtils //nicer implementation to work with than java.security.MessageDigest
import org.apache.commons.codec.binary.Hex
import org.apache.commons.codec.binary.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.collection.immutable.SortedMap

class HmacSha1 extends MessageSigner{
  //May compact the url, method, and params to a single object
  /**
   * Returns a base64 encoded string to use as an OAuth signature
   * 
   * @param key String - signing key
   * @param token String - signing token
   * @param method String - HTTP request method that will be used
   * @param url String - URL that the request will be made to
   * @param Map[String, String]() - map of key/value pairs of params that need to be included in the signature
   * 
   * @return base64 encoded String
   */
  override def createSignature(key: String, token: String, method: String, url: String, requestParams: Map[String, String]): String = {
    //First create a SortedMap which is sorted on the key from our Map
	//and then feeds that into map() to combine key and value, then into reduce to join each k,v pair with an &
	val sorted = SortedMap(requestParams.toList:_*)
	//Would it be better to just use a stringbuilder and sorted.foreach here?
	//This is more functional, but also requires two loops (map and reduceLeft) rather than just one
	val sigString = method.toUpperCase() + "&" + URLEncoder.encode(url) + "&" + 
			URLEncoder.encode(sorted.map(p => p._1 + "=" + p._2).reduceLeft{(joined,p) => joined + "&" + p})
  
	return new String(Base64.encodeBase64(generateSHA1Hash(sigString, key, token).getBytes()))
  }
  
  /**
   * Generates a SHA1 hash from the token and key
   */
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
  }
}