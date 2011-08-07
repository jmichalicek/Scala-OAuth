package jm.oauth


/**
 * Class for making signed requests after an access token has been received
 */
class Requester(val requestMethod: String, val signatureMethod: String, val consumerSecret: String, val consumerKey: String,
    val oauthToken: String, val oauthTokenSecret: String) {
  
}