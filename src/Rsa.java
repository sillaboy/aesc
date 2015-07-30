import javax.crypto.Cipher;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Rsa {
	public static final String CIPGHER_ALGORITHM = "RSA/ECB/PKCS1Padding";  
	public static final String KEY_ALGORITHM = "RSA";
    
    Key publicKey;
    Key privateKey;
    public Rsa() {
    	publicKey = null;
    	privateKey = null;
	}
    /*public Rsa(String pubkey, String priv, boolean pc) throws GeneralSecurityException
    {
    	this(pubkey, pc);
    	
        byte[] keyBytes = Base64.decryptbase64(priv.getBytes());  
        // 取得私钥  
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  

        privatekeyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
        privateKey = privatekeyFactory.generatePrivate(pkcs8KeySpec);  
    }
    public Rsa(String pubkey, boolean pc) throws GeneralSecurityException
    {
    	privateKey = null;
    	privatekeyFactory = null;
        // 对密钥解密  
        byte[] keyBytes = Base64.decryptbase64(pubkey.getBytes());  
  
        // 取得公钥  
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);  

        pubkeyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
        publicKey = pubkeyFactory.generatePublic(x509KeySpec);  
    }*/
    public Rsa(String pubkey, String priv) throws GeneralSecurityException
    {
    	this(pubkey);
    	// 对密钥解密  
        byte[] keyBytes = Base64.decryptbase64(priv.getBytes());  
  
        // 取得私钥  
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  
        KeyFactory privatekeyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        privateKey = privatekeyFactory.generatePrivate(pkcs8KeySpec);  
    }
    public Rsa(String pubkey) throws GeneralSecurityException
    {
    	privateKey = null;
        // 对密钥解密  
        byte[] keyBytes = Base64.decryptbase64(pubkey.getBytes());  
        // 取得公钥  
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);  
        KeyFactory pubkeyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
        publicKey = pubkeyFactory.generatePublic(x509KeySpec);
    }
	/** 
     * 解密<br> 
     * 用私钥解密 
     *  
     * @param data 
     * @return 
     * @throws Exception 
     */  
    public byte[] decryptByPrivateKey(byte[] data) throws Exception {
        // 对数据解密  
        Cipher cipher = Cipher.getInstance(CIPGHER_ALGORITHM);  
        cipher.init(Cipher.DECRYPT_MODE, privateKey);  
  
        return cipher.doFinal(data);  
    }  
    /** 
     * 加密<br> 
     * 用私钥加密 
     *  
     * @param data 
     * @return 
     * @throws Exception 
     */  
    public byte[] encryptByPrivateKey(byte[] data)  
            throws Exception {
        // 对数据加密  
        Cipher cipher = Cipher.getInstance(CIPGHER_ALGORITHM);  
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);  
  
        return cipher.doFinal(data);  
    }  
    /** 
     * 解密<br> 
     * 用公钥解密 
     *  
     * @param data 
     * @param key 
     * @return 
     * @throws Exception 
     */  
    public byte[] decryptByPublicKey(byte[] data) throws Exception {  
  
        // 对数据解密  
        Cipher cipher = Cipher.getInstance(CIPGHER_ALGORITHM);  
        cipher.init(Cipher.DECRYPT_MODE, publicKey);  
  
        return cipher.doFinal(data);  
    }  
    
    /** 
     * 加密<br> 
     * 用公钥加密 
     *  
     * @param data 
     * @param key 
     * @return 
     * @throws Exception 
     */  
    public byte[] encryptByPublicKey(byte[] data) throws Exception {  
        // 对数据加密  
        Cipher cipher = Cipher.getInstance(CIPGHER_ALGORITHM);  
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
  
        return cipher.doFinal(data);  
    }  
   
  
    /** 
     * 产生密钥对 
     *  
     * @return 
     * @throws Exception 
     */  
    public static void genKey() throws Exception {  
    	SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");  
        keyPairGen.initialize(1024, random);  
        KeyPair keyPair = keyPairGen.generateKeyPair();  
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        String publicKeyFilename = "publicKey";
        FileOutputStream fos = new FileOutputStream(publicKeyFilename);
        fos.write(Base64.encryptBase64(publicKeyBytes).getBytes());
        fos.close();

        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        String privateKeyFilename = "privateKey";
        fos = new FileOutputStream(privateKeyFilename);
        fos.write(Base64.encryptBase64(privateKeyBytes).getBytes());
        fos.close();

    }
}
