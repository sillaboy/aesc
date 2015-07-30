
import java.util.HashMap;
import java.util.Map;

/**
 * Created by pengoneeast on 15/7/5.
 */
public class EncryptAndDecryptJsonData {
//TODO:如何将Rsa静态化,不用每次都实例化

    public static final String RSA_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClmYhUcKVZW5g+gR33pg0XOTjB"
            + "cVsmLOnzap6XmEhNvXIKpO9i5SnsIhGCw5RxjEw4pHvvAEw3ybw4xV/Cas6/deV9"
            + "lfjPvDJ0YIKVByMCQc0+2M+bnxXyyZyMC8b2mXOYgDZhlEzZGEzOSF9+Pi/gWnM2"
            + "6NIpfulQy8E7lx4jIQIDAQAB";

    public static final String RSA_PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEA" +
            "AoGBAKWZiFRwpVlbmD6BHfemDRc5OMFxWyYs6fNqnpeYSE29cgqk72LlKewiEY" +
            "LDlHGMTDike+8ATDfJvDjFX8Jqzr915X2V+M+8MnRggpUHIwJBzT7Yz5u" +
            "fFfLJnIwLxvaZc5iANmGUTNkYTM5IX34+L+Baczbo0il+6VDLwTuXHiMhAgM" +
            "BAAECgYB7omnfKQ657SF4IOvftfB2Ezmlat0zXjr4ifSHl6D7sWHQQp2bBx7KdhD+wM" +
            "g2Ehnh/COvJ1jAGfRVqj45J4bcxVB6vtMdK3oHSIGrcybEVg1l2LYFSP5ebLlFV78a51" +
            "HvsYSVvsCopcJSLcOWRzyL3tkNAhe02sfIFMKms07WwQJBANBWxplO3DpGsLyVDms+m" +
            "0SBKvsZMuM4krGvlvvKOIEur0XuhePXOV8hBYXMYuRiXfXeWXrK5nHa+Qp+PO2i6Jk" +
            "CQQDLe8OQMtPTAFaFz/GkcgwwE2jZmyZpe3yCI2QyYBXxvF6fW4zgeNmagYsdh7oTu" +
            "a85dY1AtwM/ouh9+onklHvJAkA5z/qoTDPckAU3L32i0OqxJc7RgvqWBvreB8Wz9Tec0WGd" +
            "3ESXJwAqn7UynbbLfWhpc9wMsQUljwgQm1s47j3xAkBcCy7qMmOpBXUd8HMg7MngkVcTX+Af" +
            "RNGMWJABTX9/qrKuqQ3vmBrujfysrfGY7Jx7hFYR2PcqOPmrysHHWPcpAkEAkPk65A323MwcJ" +
            "1BaJhB+jxwndQeSLypF3zEfdmEER2sahqLf97TPkvqFUK29iF8pVTbHnnOU8A1eX8P1pEvYhw==";


    /**
     * @param String deviceJsonData 加密将要传送的数据
     * @return Map enkey存储的是经过RSA加密的随机KEY值，endata是已经经过AES加密的数据
     */
    public static Map EncryptData(String randomKey, String jsonData) throws Exception {
        //准备参数
        AESPro aesPro = new AESPro(randomKey);
        Rsa rsa = new Rsa(RSA_PUBLIC_KEY);

        //加密
        byte[] rsaEnKey = rsa.encryptByPublicKey(randomKey.getBytes());
        String enKey = Base64.encryptBase64(rsaEnKey);
        Map returnMap = new HashMap();
        returnMap.put("enkey",enKey);
        returnMap.put("endata",aesPro.encrypt(jsonData));
        return returnMap;
    }

    public static String DecryptData(String randomkey,Map enMap){
        AESPro aesPro = new AESPro(randomkey);
        return aesPro.decrypt(enMap.get("endata").toString());
    }





    public static void main(String args[]) {
        try {
            System.out.println(DecryptData("123456", EncryptData("123456", "{你好肖刚！}")));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }




}
