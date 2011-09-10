package jm.oauth

import java.net.URLDecoder
import org.apache.commons.codec.digest.DigestUtils //nicer implementation to work with than java.security.MessageDigest

import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.client.methods.HttpPost
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpRequestBase
import org.apache.http.HttpResponse
import org.apache.http.util.EntityUtils
import org.apache.http.HttpStatus

import jm.oauth.messagesigner._
import jm.oauth.MessageSigner
import jm.oauth.URLEncoder


object OAuth {
  val POST = "POST"
  val GET = "GET"
  val OOB = "oob"
  val HMAC_SHA1 = "HMAC-SHA1"
  val PLAINTEXT = "Plaintext"
  val VERSION_1 = "1.0"
    
  // takes a byte array and returns an md5hex string
  def generateNonce(toHash: Array[Byte]): String = {
    return DigestUtils.md5Hex(toHash)
  }
  
  // takes a string and returns an md5hex string
  def generateNonce(toHash: String): String = {
    return generateNonce(toHash.getBytes())
  }
}

class OAuth(val requestMethod: String, val consumerSecret: String, val consumerKey: String,
    val signatureMethod: String, val version: String = OAuth.VERSION_1) {
  
  val client = new DefaultHttpClient()
  /**
   * Returns a Map() with the key -> value pairs returned by the server
   * 
   * @param url String - url to make request to
   * @param callbackUrl String - Url for OAuth server to make callback to or OOB
   * @return Map[String,String] - Map of the returned names and values
   */
  def generateRequestToken(url: String, callbackUrl: String): Map[String,String] = {
    val epoch = System.currentTimeMillis()/1000;
    val nonce = OAuth.generateNonce(consumerKey + epoch)
    val parameters = Map("oauth_callback" -> callbackUrl,"oauth_consumer_key" -> consumerKey,
        "oauth_signature_method" -> this.signatureMethod, "oauth_timestamp" -> epoch.toString(),
        "oauth_version" -> this.version, "oauth_nonce" -> nonce)

    //val signer = this.SignatureFactory()
    val signer = MessageSigner.signatureFactory(this.signatureMethod)
    val signature = signer.createSignature(this.consumerSecret, null, this.requestMethod, url, parameters)

    //Now make request signed with signature to get the actual request token
    //TODO: Add factory with objects that do GET or POST and put the request together properly
    //val tokenRequest = new HttpPost(url)
    val tokenRequest = requestFactory(url)

    val authHeader = "OAuth realm=\"\"," + 
    	"oauth_nonce=\"" + nonce + "\"," + 
    	"""oauth_callback="oob",""" +
    	"oauth_signature_method=\"" + this.signatureMethod + "\"," +
    	"oauth_timestamp=\"" + epoch + "\"," +
        "oauth_consumer_key=\"" + consumerKey + "\"," +
        "oauth_signature=\"" + URLEncoder.encode(signature) + "\"," +
        "oauth_version=\"" + this.version + "\""
        
    tokenRequest.setHeader("Authorization", authHeader)
    
    val response = client.execute(tokenRequest)
    val responseBody = EntityUtils.toString(response.getEntity())
    
    if(response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
      //Different OAuth providers return different values and not necessarily in the same order
      //so convert that returned string to a map of key -> value pairs
    	val values = responseBody.split(('&')).foldLeft(Map[String,String]())
    			{(m,current) => m + (URLDecoder.decode(current.split('=')(0)) -> URLDecoder.decode(current.split('=')(1))) }
    	return values
    } else {
      //TODO: Better exception
      throw new Exception(responseBody)
    }
  }
  
  /**
   * Returns a Map() with the key -> value pairs returned by the server
   * 
   * @return Map[String,String]
   */
  def generateAccessToken(url: String, tokenSecret: String, oauthToken: String, oauthVerifier: String): Map[String,String] = {
    val epoch = System.currentTimeMillis()/1000;
    val nonce = OAuth.generateNonce(consumerKey + epoch)
    val parameters = Map("oauth_consumer_key" -> consumerKey, "oauth_nonce" -> nonce, 
        "oauth_signature_method" -> this.signatureMethod, "oauth_token" -> oauthToken,
        "oauth_timestamp" -> epoch.toString(),
        "oauth_verifier" -> oauthVerifier, "oauth_version" -> this.version)

    //val signer = this.SignatureFactory()
    val signer = MessageSigner.signatureFactory(this.signatureMethod)
    val signature = signer.createSignature(this.consumerSecret, tokenSecret, this.requestMethod, url, parameters)
    //println("access token signature is: " + signature)
    
    //Now make request signed with signature to get the actual request token
    val tokenRequest = requestFactory(url)
    
    val authHeader = "OAuth realm=\"\"," +
    	"oauth_consumer_key=\"" + URLEncoder.encode(consumerKey) + "\"," +
    	"oauth_nonce=\"" + nonce + "\"," + 
    	"oauth_signature_method=\"" + this.signatureMethod + "\"," +
    	"oauth_token=\"" + URLEncoder.encode(oauthToken) + "\"," +
    	"oauth_timestamp=\"" + epoch + "\"," +
    	"oauth_verifier=\"" + URLEncoder.encode(oauthVerifier) + "\"," +
        "oauth_signature=\"" + URLEncoder.encode(signature) + "\"," +
        "oauth_version=\"" + this.version + "\""
        
    tokenRequest.setHeader("Authorization", authHeader)
    
    val response = client.execute(tokenRequest)
    val responseBody = EntityUtils.toString(response.getEntity())
    
    if(response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
      //Different OAuth providers return different values and not necessarily in the same order
      //so convert that returned string to a map of key -> value pairs
    	val values = responseBody.split(('&')).foldLeft(Map[String,String]())
    			{(m,current) => m + (URLDecoder.decode(current.split('=')(0)) -> URLDecoder.decode(current.split('=')(1)))}
    	return values
    } else {
      //TODO: Better exception
      throw new Exception(responseBody)
    }
    
  }
  
  /**
   * Simple factory for HttpRequestBase objects (HttpPost and HttpGet)
   */
  def requestFactory(url: String): HttpRequestBase = {
    this.requestMethod match {
      case x if x == OAuth.GET => return new HttpGet(url)
      case x if x == OAuth.POST => return new HttpPost(url)
    }
  }
}