import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class SOAPSignerTest {

  /**
   * Load raw texfile containing xml document and wrap it using soap envelope
   */

  private SOAPMessage loadDocument(String filePath) throws SOAPException, IOException {
    try (FileInputStream fis = new FileInputStream(new File(filePath))) {
      MessageFactory factory = MessageFactory.newInstance();
      SOAPMessage message = factory.createMessage(new MimeHeaders(), fis);
      return message;
    }
  }

  /**
   * Sign SOAPMessage
   */
  public Document signSOAPMessage(SOAPMessage soapEnvelope)
    throws SOAPException, TransformerException, WSSecurityException {
    Document doc = soapEnvelope.getSOAPPart();

    final RequestData reqData = new RequestData();
    Map msgContext = new TreeMap();
    msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");
    msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "sender.properties");

    // Set this property if you want client public key (X509 certificate) sent along with document
    // server will check signature using this public key
    msgContext.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
    final String signatureParts =
      "{}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;" +
        "{}{http://www.w3.org/2005/08/addressing}To;" +
        "{}{http://www.w3.org/2005/08/addressing}Action;" +
        "{}{http://www.w3.org/2005/08/addressing}ReplyTo;" +
        "{}{http://schemas.xmlsoap.org/soap/envelope/}Body;";

    msgContext.put(WSHandlerConstants.SIGNATURE_PARTS, signatureParts);

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

  /**
   * Save Document to file
   *
   * @param doc  Document to be persisted
   * @param file output file
   * @throws FileNotFoundException
   * @throws TransformerException
   */
  public void persistDocument(Document doc, String file)
    throws IOException, TransformerException {
    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    try (FileOutputStream fos = new FileOutputStream(file)) {
      DOMSource source = new DOMSource(doc);
      transformer.transform(source, new StreamResult(fos));
    }
  }

  /**
   * Check signed documents
   *
   * @param signedDoc
   * @throws WSSecurityException
   * @throws FileNotFoundException
   * @throws ParserConfigurationException
   * @throws SAXException
   * @throws IOException
   * @throws SOAPException
   */
  public void checkSignedDoc(Document signedDoc)
    throws WSSecurityException, FileNotFoundException,
    ParserConfigurationException, SAXException, IOException,
    SOAPException {
    Crypto crypto = CryptoFactory.getInstance("receiver.properties");
    WSSecurityEngine engine = new WSSecurityEngine();
    // TODO
    WSSConfig config = WSSConfig.getNewInstance();
    //   config.setWsiBSPCompliant(false); // TODO
    engine.setWssConfig(config);

    // process verification
    WSHandlerResult res = engine.processSecurityHeader(signedDoc,
      null, null, crypto);

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

  public static void main(String... args) throws ParserConfigurationException, SAXException, IOException, SOAPException, TransformerException, WSSecurityException {
    SOAPSignerTest digsigDemo = new SOAPSignerTest();

    System.out.println("Creating SOAPMessages from xml file");
    SOAPMessage msg = digsigDemo.loadDocument("/home/remco/git/wss4j/src/main/resources/in.xml");

    System.out.println("Sign document");
    Document signedDoc = digsigDemo.signSOAPMessage(msg);

    System.out.println("Check generated signature");
    digsigDemo.checkSignedDoc(signedDoc);

    System.out.println("Persist signed document to file");
    digsigDemo.persistDocument(signedDoc, "/home/remco/git/wss4j/src/main/resources/out.xml");

    System.out.println("Process finished");
  }
}

