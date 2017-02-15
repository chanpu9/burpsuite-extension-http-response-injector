package burp;

import java.io.PrintWriter;

/**
 * Simple class to keep logging seperate
 * @author cmcneill
 *
 */
public class Logger {

	private PrintWriter stdOut;
	private PrintWriter stdError;
	private IBurpExtenderCallbacks callbacks;

	public Logger(IBurpExtenderCallbacks callbacks) {
		stdOut = new PrintWriter(callbacks.getStdout(), true);
		stdError = new PrintWriter(callbacks.getStderr(), true);
	}

	// write a message to the Burp alerts tab
	public void alert(String alertMessage) {
		callbacks.issueAlert(alertMessage);
	}
	
	public void alert(String message, Object... args){
		alert(String.format(message, args));
	}

	// write a message to our output stream
	public void info(String logMessage) {
		stdOut.println(logMessage);
	}
	
	public void info(String message, Object... args){
		info(String.format(message, args));
	}

	// write a message to our error stream
	public void error(String errorMessage) {
		stdError.println(errorMessage);
	}
	
	public void error(String message, Object... args){
		error(String.format(message, args));
	}

}
