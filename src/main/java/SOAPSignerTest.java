import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.SignatureActionToken;
import org.apache.wss4j.common.crypto.CertificateStore;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Pattern;

public class SOAPSignerTest {

  private SOAPMessage loadDocument(String filePath) throws SOAPException, IOException {
    try (FileInputStream fis = new FileInputStream(new File(filePath))) {
      MessageFactory factory = MessageFactory.newInstance();
      SOAPMessage message = factory.createMessage(new MimeHeaders(), fis);
      return message;
    }
  }

  public Document signSOAPMessage(SOAPMessage soapEnvelope)
    throws SOAPException, TransformerException, WSSecurityException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    Document doc = soapEnvelope.getSOAPPart();

    final RequestData reqData = new RequestData();
    KeyStore keysStore = loadKeys("keystore.jks");
    Crypto crypto = new MemoryCrypto(keysStore);
    SignatureActionToken token = new SignatureActionToken();
    token.setCrypto(crypto);
    reqData.setSignatureToken(token);

    Map msgContext = new TreeMap();
    msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");

    // Set this property if you want client public key (X509 certificate) sent along with document
    // server will check signature using this public key
    msgContext.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
    final String signatureParts =
      "{}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;" +
        "{}{http://www.w3.org/2005/08/addressing}To;" +
        "{}{http://www.w3.org/2005/08/addressing}Action;" +
        "{}{http://www.w3.org/2005/08/addressing}ReplyTo;" +
        "{}{http://schemas.xmlsoap.org/soap/envelope/}Body;";

    msgContext.put(ConfigurationConstants.SIGNATURE_PARTS, signatureParts);
    msgContext.put(ConfigurationConstants.SIG_ALGO, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

    msgContext.put("password", "changeit");
    reqData.setMsgContext(msgContext);
    reqData.setUsername("clientca3");


    final List<HandlerAction> actions = new ArrayList();
    actions.add(new HandlerAction(WSConstants.TS));
    actions.add(new HandlerAction(WSConstants.SIGN));

    CustomHandler handler = new CustomHandler();

    // sign document
    handler.send(doc, reqData, actions, true);


    return doc;
  }

  public void persistDocument(Document doc, String file)
    throws IOException, TransformerException {
    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    try (FileOutputStream fos = new FileOutputStream(file)) {
      DOMSource source = new DOMSource(doc);
      transformer.transform(source, new StreamResult(fos));
    }
  }

  class MemoryCrypto extends org.apache.wss4j.common.crypto.CryptoBase {
    KeyStore keyStore;
    PrivateKey privateKey;

    MemoryCrypto(KeyStore keyStore) {
      this.keyStore = keyStore;
      try {
        privateKey = (PrivateKey) keyStore.getKey("clientca3", "changeit".toCharArray());
      } catch (KeyStoreException e) {
        e.printStackTrace();
      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
      } catch (UnrecoverableKeyException e) {
        e.printStackTrace();
      }
    }

    @Override
    public X509Certificate[] getX509Certificates(CryptoType cryptoType) throws WSSecurityException {
      try {
        return new X509Certificate[]{(X509Certificate) keyStore.getCertificate("clientca3")};
      } catch (KeyStoreException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public String getX509Identifier(X509Certificate cert) throws WSSecurityException {
      throw new IllegalArgumentException();
    }

    @Override
    public PrivateKey getPrivateKey(X509Certificate certificate, CallbackHandler callbackHandler) throws WSSecurityException {
      throw new IllegalArgumentException();
    }

    @Override
    public PrivateKey getPrivateKey(String identifier, String password) throws WSSecurityException {
      return privateKey;
    }

    @Override
    public void verifyTrust(X509Certificate[] certs, boolean enableRevocation, Collection<Pattern> subjectCertConstraints) throws WSSecurityException {
      throw new IllegalArgumentException();
    }

    @Override
    public void verifyTrust(PublicKey publicKey) throws WSSecurityException {
      throw new IllegalArgumentException();
    }
  }

  public void checkSignedDoc(Document signedDoc)
    throws WSSecurityException, FileNotFoundException,
    ParserConfigurationException, SAXException, IOException,
    SOAPException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
    //
//    KeyStore keyStore = loadKeys("cacerts");
    KeyStore keyStore = loadKeys("keystore.jks");
    Crypto crypto = new CertificateStore(getX509Certificates(keyStore));
    WSSecurityEngine engine = new WSSecurityEngine();
    // TODO
    WSSConfig config = WSSConfig.getNewInstance();
    //   config.setWsiBSPCompliant(false); // TODO
    engine.setWssConfig(config);

    // process verification
    WSHandlerResult res = engine.processSecurityHeader(signedDoc,
      null, null, crypto);
    if (res == null) {
      throw new RuntimeException("No signature");
    }
    for (WSSecurityEngineResult ers : res.getResults()) {
      if (ers.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN) != null) {

        // You can get certificate sent by client here
        System.out.println(ers
          .get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN));

        // You can get certificate info (used to sign document) here
        X509Certificate cert = (X509Certificate) ers
          .get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        System.out.println(cert.getSubjectDN());
      }
    }
  }

  private X509Certificate[] getX509Certificates(KeyStore keysStore) throws KeyStoreException {
    List<X509Certificate> certificates = new ArrayList<>();

    Enumeration<String> aliases = keysStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      Certificate[] chain = keysStore.getCertificateChain(alias);
      if (chain == null) {
        Certificate cert = keysStore.getCertificate(alias);
        if (cert != null) {
          System.err.println("Only cert for " + alias);
        } else {
          System.err.println("No chain for " + alias);
        }
      } else {
        System.err.println("Chain for " + alias);
        for (Certificate certificate : chain) {
          if (certificate instanceof X509Certificate) {
            certificates.add((X509Certificate) certificate);
          }
        }
      }
    }
    return certificates.toArray(new X509Certificate[certificates.size()]);
  }

  public static void main(String... args) throws ParserConfigurationException, SAXException, IOException, SOAPException, TransformerException, WSSecurityException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
    WSSConfig.setAddJceProviders(false);
    org.apache.xml.security.Init.init();
    SOAPSignerTest digsigDemo = new SOAPSignerTest();

    System.out.println("Creating SOAPMessages from xml file");
    SOAPMessage msg = digsigDemo.loadDocument("/home/remco/git/wss4j/src/main/resources/in.xml");

    System.out.println("Sign document");
    Document signedDoc = digsigDemo.signSOAPMessage(msg);
    signedDoc.normalizeDocument();
    System.out.println("Check generated signature");
    digsigDemo.checkSignedDoc(msg.getSOAPPart());

    System.out.println("Persist signed document to file");
   digsigDemo.persistDocument(msg.getSOAPPart(), "/home/remco/git/wss4j/src/main/resources/out.xml");

    System.out.println("Process finished");
  }

  KeyStore loadKeys(String keyStoreFilename) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableKeyException {
    KeyStore ks = KeyStore.getInstance("JKS");
    InputStream readStream = new FileInputStream(keyStoreFilename);
    ks.load(readStream, "changeit".toCharArray());
    Key key = ks.getKey("keyAlias", "changeit".toCharArray());
    readStream.close();
    return ks;
  }
}

