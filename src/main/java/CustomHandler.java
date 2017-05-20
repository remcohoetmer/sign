import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandler;
import org.apache.wss4j.dom.handler.WSHandlerResult;
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
    Document doc,
    RequestData reqData,
    List<HandlerAction> actions,
    boolean request
  ) throws WSSecurityException {
    doSenderAction(
      doc,
      reqData,
      actions,
      request
    );
  }

  public void receive(
    List<Integer> actions,
    RequestData reqData
  ) throws WSSecurityException {
    doReceiverAction(
      actions,
      reqData
    );
  }

  public void signatureConfirmation(
    RequestData requestData,
    WSHandlerResult handlerResults
  ) throws WSSecurityException {
    checkSignatureConfirmation(requestData, handlerResults);
  }

  public boolean checkResults(
    List<WSSecurityEngineResult> results,
    List<Integer> actions
  ) throws WSSecurityException {
    return checkReceiverResults(results, actions);
  }

  public boolean checkResultsAnyOrder(
    List<WSSecurityEngineResult> results,
    List<Integer> actions
  ) throws WSSecurityException {
    return checkReceiverResultsAnyOrder(results, actions);
  }


}