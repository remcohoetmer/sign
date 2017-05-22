import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandler;
import org.w3c.dom.Document;

import java.util.List;
import java.util.Map;

public class CustomHandler extends WSHandler {
  public Object
  getOption(String key) {
    return null;
  }

  @SuppressWarnings("unchecked")
  public void
  setProperty(
    Object ctx,
    String key,
    Object value
  ) {
    ((Map<String, Object>) ctx).put(key, value);
  }

  public Object
  getProperty(Object ctx, String key) {
    if (ctx instanceof Map<?, ?>) {
      return ((Map<?, ?>) ctx).get(key);
    }
    return null;
  }

  public void setPassword(Object msgContext, String password) {
  }

  public String getPassword(Object msgContext) {
    return "";
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
}