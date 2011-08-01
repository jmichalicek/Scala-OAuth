package jm.oauth

trait MessageSigner {
  def createSignature(key: String, token: String, method: String, url: String, requestParams: Map[String, String]): String = {
    return null
  }

}