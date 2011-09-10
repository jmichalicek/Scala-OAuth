package jm.oauth.messagesigner

import jm.oauth.MessageSigner
import java.net.URLEncoder

class Plaintext extends MessageSigner {
	override def createSignature(key: String, token: String, method: String, url: String, requestParams: Map[String, String]): String = {
	  val signature = key + (token match {
	    case x if x != null => "&" + token
	    case x => "&"
	  })
	  
	  return signature
	}
}