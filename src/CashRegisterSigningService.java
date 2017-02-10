/*
 * Copyright (c) 2017, Florian Pflug
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import com.sun.net.httpserver.*;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

import at.atrust.cashregister.*;

public class CashRegisterSigningService {
	
	private final static Logger LOGGER = Logger.getLogger(CashRegisterSigningService.class.getName());
	
	private static String ENDPOINT = "/sign";
	
	private static String PIN = "123456";
	
	private static ICashRegisterSmartCard cashRegisterSmartCard;
	
	static class SigningException extends Exception {
        private static final long serialVersionUID = 1L;

        final String clientMessage;
        final int clientCode;
        
        SigningException(int _clientCode, String _clientMessage, String logMessage) {
        	super(logMessage);
        	clientCode = _clientCode;
        	clientMessage = _clientMessage;
        }

        SigningException(int _clientCode, String _message) {
        	super(_message);
        	clientCode = _clientCode;
        	clientMessage = _message;
        }

        SigningException(int _clientCode, String _clientMessage, String logMessage, Throwable cause) {
        	super(logMessage);
        	clientCode = _clientCode;
        	clientMessage = _clientMessage;
        }
        
        SigningException(int _clientCode, String _message, Throwable cause) {
        	super(_message, cause);
        	clientCode = _clientCode;
        	clientMessage = _message;
        }

	}

	private static void getCashRegisterSmartCardInstance() throws SigningException {
		try {
			LOGGER.log(Level.FINE, "initializing cash register smart card");
			
			/* Open card API */
			TerminalFactory terminalFactory;
			try {
				terminalFactory = TerminalFactory.getInstance("PC/SC", null);
			} catch (NoSuchAlgorithmException e) {
				terminalFactory = TerminalFactory.getDefault();
			}
			LOGGER.log(Level.FINEST, "using card terminal factory " + terminalFactory.toString());

			/* Enumerate card terminals, connect to inserted card */
			final List<CardTerminal> cardTerminals = terminalFactory.terminals().list(CardTerminals.State.CARD_PRESENT);
			if (cardTerminals.isEmpty())
				throw new SmartCardException("no card terminal with inserted smart card found");
			final CardTerminal cardTerminal = cardTerminals.get(0);
			LOGGER.log(Level.FINEST, "found " + cardTerminals.size() + " terminals with inserted smart card, will use first one");

			final Card card = cardTerminal.connect("*");
			LOGGER.log(Level.FINEST, "found smart card " + card.toString());
			
	        cashRegisterSmartCard = CashRegisterSmartCardFactory.createInstance(card);
			LOGGER.log(Level.INFO,
			           "initialized cash register smart card for subject " + cashRegisterSmartCard.getCertificate().getSubject().toString());
		}
		catch (Exception e) {
			cashRegisterSmartCard = null;
			LOGGER.log(Level.SEVERE, "failed to initialize cash register smart card", e);
			throw new SigningException(500, "token unavailable", "connection to smart card failed", e);	
		}
	}
	
	private static byte[] sign(byte[] hash) throws SigningException {
		/* If card is already initialized, use it to sign */
		if (cashRegisterSmartCard != null) {
			try {
				LOGGER.log(Level.FINE, "executing signature request using existing connection, hash is " + Arrays.toString(hash));
				final byte[] signature = cashRegisterSmartCard.doSignatur(hash, PIN);
				LOGGER.log(Level.FINE, "request succeeded, signature is " + Arrays.toString(signature));
				return signature;
			}
			catch (SmartCardException e) {
				LOGGER.log(Level.WARNING, "signature request using existing connection failed, will reconnect and retry", e);
				/* If the signature request fails, try to re-initialize card */
			}
		}
		
		/* (Re-)Initialize card if no initialized card is available, or the request above failed */
		getCashRegisterSmartCardInstance();
		
		/* Re-execute signature request using freshly initialized card */
		try {
			LOGGER.log(Level.FINE, "executing signature request using freshly initialized card, hash is " + Arrays.toString(hash));
			final byte[] signature = cashRegisterSmartCard.doSignatur(hash, PIN);
			LOGGER.log(Level.FINE, "request succeeded, signature is " + Arrays.toString(signature));
			return signature;
		}
		catch (SmartCardException e) {
			/* Connection is fresh, no point in trying to re-initialize again, pass on failure */
			LOGGER.log(Level.SEVERE, "signature request using freshly initialized card failed", e);
			throw new SigningException(500, "token unavailable", "signature request failed", e);	
		}
	}

    private static Map<String,String> getQueryParameters(HttpExchange httpExchange)
    {
        Map<String, String> result = new java.util.HashMap<String, String>();
        if (httpExchange.getRequestURI().getQuery() == null)
        	return result;
    	for(String param: httpExchange.getRequestURI().getQuery().split("&")) {
    		final String[] pair = param.split("=", 2);
    		switch(pair.length) {
    			case 1: result.put(pair[0], ""); break;
    			case 2: result.put(pair[0], pair[1]); break;
    		}
    	}
    	return result;
    }

    static class SignHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
        	try {
        		LOGGER.log(Level.INFO, "Request " + t.getRequestMethod() + " " + t.getRequestURI().toString());
        		
        		/* Only allow access from local host */
        		if (!t.getRemoteAddress().getAddress().isLoopbackAddress())
            		throw new SigningException(403, "request denied", "client must have address 127.0.0.1");

        		/* Only allow GET requests */
        		if (!t.getRequestMethod().equals("GET"))
            		throw new SigningException(403, "request denied", t.getRequestMethod() + " unsupported, only GET is allowed");
        		
        		if (!t.getRequestURI().getPath().equals(ENDPOINT))
            		throw new SigningException(404, "not found", t.getRequestURI().getPath() + " unsupported, only " + ENDPOINT + " is allowed");

            	/* Decode request parameters */
            	Map<String, String> urlParams = getQueryParameters(t);
            	
            	/* Handle parameter <hash> */
            	final String urlHash = urlParams.get("hash");
            	if (urlHash == null)
            		throw new SigningException(400, "parameter <hash> missing");
            	final byte[] hash;
            	try {
            		hash = Base64.getUrlDecoder().decode(urlHash);
            	}
            	catch (IllegalArgumentException e) {
            		throw new SigningException(400, "parameter <hash> not in Base64Url format", e);
            	}
            	if (hash.length != 32)
            		throw new SigningException(400, "parameter <hash> has invalid length " + hash.length + " after Base64Url decoding (should be 32");
            		
        		/* Url-decode hash, sign, and base64-encode signature */
	            final String signature = Base64.getUrlEncoder().encodeToString(sign(hash));
	            
	            /* Send signature as HTTP response body */
	            t.sendResponseHeaders(200, signature.length());
	            final OutputStream os = t.getResponseBody();
	            os.write(signature.getBytes());
	            os.close();
	            
	            /* Log */
        		LOGGER.log(Level.INFO, "Request succeeded, responded '" + signature + "'");
            }
            catch (SigningException e) {
            	/* Signing failed. Send error message as response body */
            	final String error = e.clientMessage;
	            t.sendResponseHeaders(e.clientCode, error.length());
	            final OutputStream os = t.getResponseBody();
	            os.write(error.getBytes());
	            os.close();
            	
	            /* And log error */
        		LOGGER.log(Level.SEVERE, "Request failed, " + e.getMessage());
            }
            catch (Exception e) {
            	/* Signing failed. Send error message as response body */
            	final String error = "internal server error";
	            t.sendResponseHeaders(500, error.length());
	            final OutputStream os = t.getResponseBody();
	            os.write(error.getBytes());
	            os.close();
            	
	            /* And log error */
        		LOGGER.log(Level.SEVERE, "Request failed", e);
            }
        }
    }
    
    public static void main(String[] args) throws Exception {
    	/* Remove default "console" log handler */
    	final Logger rootLogger = Logger.getLogger("");
    	for(Handler handler : rootLogger.getHandlers())
    		rootLogger.removeHandler(handler);
    	rootLogger.setLevel(Level.ALL);
    	
    	/* Log everything to the console */
    	final ConsoleHandler consoleHandler = new ConsoleHandler();
    	consoleHandler.setLevel(Level.ALL);
    	rootLogger.addHandler(consoleHandler);
    	
    	/* Log to file "requests.log" */
    	final FileHandler logHandler = new FileHandler("requests.log", true /* append */);
    	logHandler.setLevel(Level.INFO);
    	logHandler.setFormatter(new SimpleFormatter());
    	rootLogger.addHandler(logHandler);
    	
    	/* Create Handler which handles signature requests (GET requests to ENDPOINT) */
        final SignHandler handler = new SignHandler();

        /* Create HTTP server, router requests to ENDPOINT to the handler,
         * and let everything execute on the same threshold (null executor)
         */
        final HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 1337), 0);
        server.createContext(ENDPOINT, handler);
        server.setExecutor(null);
        LOGGER.log(Level.INFO, "Created HTTP server, listening on http:/" + server.getAddress() + ENDPOINT);
        
        /* Start server */
        server.start();
    }    
 }
