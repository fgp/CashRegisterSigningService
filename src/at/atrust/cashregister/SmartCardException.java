/*
 * Code published by A-Trust, see
 * 
 *   http://labs.a-trust.at/developer/ShowSource.aspx?id=114
 */

package at.atrust.cashregister;

/**
 * Created by chinnow on 16.10.2015.
 */
public class SmartCardException extends Exception {

	private static final long serialVersionUID = 5377974919590757907L;

	public SmartCardException(Exception e) {
		super(e);
	}

	public SmartCardException(String message) {
		super(message);
	}
}
