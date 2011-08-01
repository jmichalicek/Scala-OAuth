package httpTest

import java.net.URLEncoder
import org.apache.commons.codec.digest.DigestUtils //nicer implementation to work with than java.security.MessageDigest

import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils

import org.apache.http.HttpStatus

import jm.oauth.messagesigner._


object OAuth {
  val POST = "POST"
  val GET = "GET"
  val OOB = "oob"
  val HMAC_SHA1 = "HMAC-SHA1"
  val PLAINTEXT = "Plaintext"
}

class OAuth(val requestMethod: String, val consumerSecret: String, val consumerKey: String, val signatureMethod: String) {
  val client = new DefaultHttpClient()
  
  def generateNonce(salt: Array[Byte]): String = {
    return DigestUtils.md5Hex(salt)
  }
  
  def generateNonce(salt: String): String = {
    return generateNonce(salt.getBytes())
  }
  /**
   * Returns a tuple3 with the oauth_token, oauth_token_secret, and oauth_callback_confirmed values
   * 
   * @return (oauth_token, oauth_token_secret, oauth_callback_confirmed)
   */
  def generateRequestToken(method: String, url: String, callbackUrl: String): Tuple3[String,String,String] = {
    val epoch = System.currentTimeMillis()/1000;
    val nonce = generateNonce(consumerKey + epoch)
    val parameters = Map("oauth_callback" -> callbackUrl,"oauth_consumer_key" -> consumerKey,
        "oauth_signature_method" -> this.signatureMethod, "oauth_timestamp" -> epoch.toString(), "oauth_version" -> "1.0",
        "oauth_nonce" -> nonce)
        
    //TODO: Create factory for these as it could be any of 3
    //val signer = new HmacSha1()
    val signer = this.SignatureFactory()
    val signature = signer.createSignature(this.consumerSecret, null, method, url, parameters)

    //Now make request signed with signature to get the actual request token
    val tokenRequest = new HttpPost(url)

    val authHeader = "OAuth realm=\"\"," + 
    	"oauth_nonce=\"" + nonce + "\"," + 
    	"""oauth_callback="oob",""" +
    	"oauth_signature_method=\"" + this.signatureMethod + "\"," +
    	"oauth_timestamp=\"" + epoch + "\"," +
        "oauth_consumer_key=\"" + consumerKey + "\"," +
        "oauth_signature=\"" + URLEncoder.encode(signature) + "\"," +
        "oauth_version=\"1.0\""
        
    tokenRequest.setHeader("Authorization", authHeader)
    
    val response = client.execute(tokenRequest)
    //There is currently an assumption that this worked!
    //Need to throw an exception if this did not work
    val responseBody = EntityUtils.toString(response.getEntity())
    if(response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
    	val values = responseBody.split(('&')).map(current => current.split('=')(1))
    	return (values(0),values(1),values(2))
    } else {
      throw new Exception(responseBody)
    }
  }
  
  def SignatureFactory(): jm.oauth.MessageSigner = {
    this.signatureMethod match {
      case x if x == OAuth.HMAC_SHA1 => return new HmacSha1()
      case x if x == OAuth.PLAINTEXT => return new Plaintext()
    }
  }
}