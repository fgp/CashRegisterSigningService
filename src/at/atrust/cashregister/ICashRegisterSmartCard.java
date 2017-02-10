/*
 * Code published by A-Trust, see
 * 
 *   http://labs.a-trust.at/developer/ShowSource.aspx?id=114
 */

package at.atrust.cashregister;

import javax.smartcardio.CardException;

import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Created by chinnow on 03.05.2016.
 */
public interface ICashRegisterSmartCard {

	String getImplementationName();
	
	byte[] doSignatur(byte[] sha256Hash, String pin) throws SmartCardException;

	byte[] doSignaturWithoutSelection(byte[] sha256Hash, String pin) throws SmartCardException;

	String getCertificateSerialDecimal() throws SmartCardException, CardException;

	String getCertificateSerialHex() throws SmartCardException, CardException;

	X509CertificateHolder getCertificate() throws SmartCardException, CardException;

	String getCIN() throws SmartCardException, CardException;

}
