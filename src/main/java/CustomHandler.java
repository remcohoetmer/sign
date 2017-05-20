
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.RequestData;
import org.w3c.dom.Document;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * A trivial extension of the WSHandler type for use in unit-testing.
 */
public class CustomHandler extends WSHandler {

  private Map<String, Object> optionsMap = new HashMap<String, Object>();

  public Object
  getOption(String key) {
    return optionsMap.get(key);
  }

  public void
  setOption(String key, Object option) {
    optionsMap.put(key, option);
  }

  @SuppressWarnings("unchecked")
  public void
  setProperty(
    Object ctx,
    String key,
    Object value
  ) {
    ((Map<String, Object>)ctx).put(key, value);
  }

  public Object
  getProperty(Object ctx, String key) {
    if (ctx instanceof Map<?,?>) {
      return ((Map<?,?>)ctx).get(key);
    }
    return null;
  }

  public void
  setPassword(Object msgContext, String password) {
  }

  public String
  getPassword(Object msgContext) {
    if (msgContext instanceof Map<?,?>) {
      return (String)((Map<?,?>)msgContext).get("password");
    }
    return null;
  }

  public void send(
    int action,
    Document doc,
    RequestData reqData,
    List<Integer> actions,
    boolean request
  ) throws org.apache.ws.security.WSSecurityException {
    doSenderAction(
      action,
      doc,
      reqData,
      actions,
      request
    );
  }

  public void receive(
    int action,
    RequestData reqData
  ) throws org.apache.ws.security.WSSecurityException {
    doReceiverAction(
      action,
      reqData
    );
  }

  public void signatureConfirmation(
    RequestData requestData,
    List<WSSecurityEngineResult> results
  ) throws org.apache.ws.security.WSSecurityException {
    checkSignatureConfirmation(requestData, results);
  }

  public boolean checkResults(
    List<WSSecurityEngineResult> results,
    List<Integer> actions
  ) throws org.apache.ws.security.WSSecurityException {
    return checkReceiverResults(results, actions);
  }

  public boolean checkResultsAnyOrder(
    List<WSSecurityEngineResult> results,
    List<Integer> actions
  ) throws org.apache.ws.security.WSSecurityException {
    return checkReceiverResultsAnyOrder(results, actions);
  }


}