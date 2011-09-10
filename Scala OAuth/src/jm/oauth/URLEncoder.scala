package jm.oauth

//Scala-fied from http://stackoverflow.com/questions/724043/http-url-address-encoding-in-java/4605816#4605816
//because the java and apache commons solutions don't do proper url encoding, they do x-www.form-urlencoded
object URLEncoder {
  def encode(toEncode: String): String = {
    val encoded = new StringBuilder()
    
    for(ch <- toEncode.toCharArray()) {
      if (isUnsafe(ch)) {
        encoded.append('%')
        encoded.append(toHex(ch / 16));
        encoded.append(toHex(ch % 16));
      } else {
        encoded.append(ch)
      }
    }
    
    return encoded.toString()
  }
  
  def toHex(ch: Int): Char = {
    return (if(ch < 10) '0' + ch else 'A' + ch - 10).toChar
  }
  
  def isUnsafe(ch: Char): Boolean = {
    if (ch > 128 || ch < 0) {
      return true;
    }
    return " %$&+,/:;=?@<>#%".indexOf(ch) >= 0;
  }

}