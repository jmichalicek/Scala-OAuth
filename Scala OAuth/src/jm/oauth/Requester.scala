package jm.oauth

import org.apache.http.client.entity.UrlEncodedFormEntity
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.client.methods.HttpPost
import org.apache.http.client.methods.HttpGet
import org.apache.http.HttpResponse
import org.apache.http.HttpStatus
import org.apache.http.util.EntityUtils

import jm.oauth.MessageSigner
import jm.oauth.messagesigner._
import jm.oauth.URLEncoder

/**
 * Class for making signed requests after an access token has been received
 * 
 * @param signatureMethod String - the type of signature to use for requests
 * @param consumerSecret String - the OAuth consumer secret
 * @param consumerKey String - the OAuth consumer key
 * @param oauthToken String - the OAuth token from an access token request
 * @param oauthTokenSecret String - the OAuth token secret from an access token request
 * @param version String - the OAuth version.  Defaults to 1.0
 */
class Requester(val signatureMethod: String, val consumerSecret: String, val consumerKey: String,
    val oauthToken: String, val oauthTokenSecret: String, val version: String = OAuth.VERSION_1) {

  //This class could potentially be reused to make the request_token and access_token
  //requests as well if the auth header and signature params are abstracted further
  //but I am trying to keep the user's work minimal at the moment
  
  val signer = MessageSigner.signatureFactory(this.signatureMethod)
  val client = new DefaultHttpClient()
  
  // What about plain old postdata with no name?
  // I think that is not specified as part of the OAuth spec
  /**
   * Perform an OAuth signed HTTP POST
   * 
   * @param url String - The URL to POST to
   * @param postParams Map[String, String]() - Map of POST parameter names and values
   */
  
  //What if we need to return a non-string, like an image?
  //may be best to return something more generic like the request object
  def post(url: String, postParams: Map[String, String]): Array[Byte] = {
    val epoch = System.currentTimeMillis()/1000;
    val nonce = OAuth.generateNonce(consumerKey + epoch)
    
    //POST params need URL encoded values once before being used in the signature where they will be encoded again
    val parameters = Map("oauth_consumer_key" -> this.consumerKey, "oauth_signature_method" -> this.signatureMethod,
        "oauth_timestamp" -> epoch.toString(), "oauth_version" -> this.version, "oauth_token" -> this.oauthToken,
        "oauth_nonce" -> nonce) ++ encodeMapValues(postParams)
        
    val signer = MessageSigner.signatureFactory(this.signatureMethod)
    val signature = signer.createSignature(this.consumerSecret, this.oauthTokenSecret, OAuth.POST, url, parameters)
    
    val request = new HttpPost(url)
    //what if user needs to specify the realm?
    val realm = request.getURI().getScheme() + "://" + request.getURI().getHost() + "/"
    val authHeader = "OAuth realm=\"" + realm + "\"," +
    	"oauth_consumer_key=\"" + URLEncoder.encode(this.consumerKey) + "\"," +
    	"oauth_nonce=\"" + nonce + "\"," + 
    	"oauth_signature_method=\"" + this.signatureMethod + "\"," +
    	"oauth_token=\"" + URLEncoder.encode(this.oauthToken) + "\"," +
    	"oauth_timestamp=\"" + epoch + "\"," +
        "oauth_signature=\"" + URLEncoder.encode(signature) + "\"," +
        "oauth_version=\"" + this.version + "\""
        
    request.addHeader("Authorization", authHeader)

    //Twitter examples seem to want these percent encoded, not x-www-form-urlencoded even though it's a POST parameter
    //This actually x-www-form-urlencodes, and it seems to work    
    val pList = new java.util.ArrayList[BasicNameValuePair]()
    postParams.foreach {case (name, value) => pList.add(new BasicNameValuePair(name,value))}
    request.setEntity(new UrlEncodedFormEntity(pList))
    
    //request.setEntity(new StringEntity("status=" + URLEncoder.encode(postParams("status")))) //Ends up in postdata. Could be useful later
    
    val response = client.execute(request)
    //Return a byte array because this could be anything.
    //It's likely a string, but it's really easy to convert byte arrays to strings
    val responseBody = EntityUtils.toByteArray(response.getEntity())

    return responseBody
  }
  
  /**
   * Perform an OAuth signed HTTP GET
   * 
   * @param url String - The URL to GET without querystring parameters
   * @param getParams Map[String, String]() - Map of querystring parameter names and values
   */
  def get(url: String, getParams: Map[String, String]): Array[Byte] = {
    val epoch = System.currentTimeMillis()/1000;
    val nonce = OAuth.generateNonce(consumerKey + epoch)
    
    //query params need URL encoded values once before being used in the signature where they will be encoded again
    val parameters = Map("oauth_consumer_key" -> this.consumerKey, "oauth_signature_method" -> this.signatureMethod,
        "oauth_timestamp" -> epoch.toString(), "oauth_version" -> this.version, "oauth_token" -> this.oauthToken,
        "oauth_nonce" -> nonce) ++ encodeMapValues(getParams)
        
    //Map() converted to list of String with map() and then joined with & using reduceLeft
    //StringBuilder and foreach may be more appropriate
    val queryString = getParams.map(p =>
      java.net.URLEncoder.encode(p._1) + "=" + java.net.URLEncoder.encode(p._2))
      .reduceLeft{(joined,p) => joined + "&" + p}
    
    val signer = MessageSigner.signatureFactory(this.signatureMethod)
    val signature = signer.createSignature(this.consumerSecret, this.oauthTokenSecret, OAuth.GET, url, parameters)
    
    val request = new HttpGet(url + "?" + queryString)
    val realm = request.getURI().getScheme() + "://" + request.getURI().getHost() + "/"
    val authHeader = "OAuth realm=\"" + realm + "\"," +
    	"oauth_consumer_key=\"" + URLEncoder.encode(this.consumerKey) + "\"," +
    	"oauth_nonce=\"" + nonce + "\"," + 
    	"oauth_signature_method=\"" + this.signatureMethod + "\"," +
    	"oauth_token=\"" + URLEncoder.encode(this.oauthToken) + "\"," +
    	"oauth_timestamp=\"" + epoch + "\"," +
        "oauth_signature=\"" + URLEncoder.encode(signature) + "\"," +
        "oauth_version=\"" + this.version + "\""
        
    request.addHeader("Authorization", authHeader)

    val response = client.execute(request)
    //Return a byte array because this could be anything.
    //It's likely a string, but it's really easy to convert byte arrays to strings
    val responseBody = EntityUtils.toByteArray(response.getEntity())
    return responseBody
  }
  
  /**
   * Returns Map() with the value URL encoded
   * 
   * @param toEncode Map[String, String]()
   * @return Map[String, String]()
   */
  def encodeMapValues(toEncode: Map[String, String]): Map[String, String] = {
    val encoded = toEncode.foldLeft(Map[String, String]()) {(encoding, current) => encoding + (current._1 -> URLEncoder.encode(current._2))}
    
    return encoded
  }
  
}