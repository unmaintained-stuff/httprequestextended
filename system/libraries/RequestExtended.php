<?php if (!defined('TL_ROOT')) die('You can not access this file directly!');

/**
 * TYPOlight webCMS
 *
 * The TYPOlight webCMS is an accessible web content management system that 
 * specializes in accessibility and generates W3C-compliant HTML code. It 
 * provides a wide range of functionality to develop professional websites 
 * including a built-in search engine, form generator, file and user manager, 
 * CSS engine, multi-language support and many more. For more information and 
 * additional TYPOlight applications like the TYPOlight MVC Framework please 
 * visit the project website http://www.typolight.org.
 * 
 * PHP version 5
 * @copyright	Christian Schiffler <c.schiffler@cyberspectrum.de>
 * @package		RequestExtended
 * @license		LGPL 
 * @filesource
 */

/**
 * Class Request11
 *
 * Provide methods to handle HTTP 1.1 requests. This class uses some functions of
 * Drupal's HTTP request class that you can find on http://drupal.org.
 * Based upon the TL core Request class by Leo Feyer <leo@typolight.org>
 * Proxy functionality is heavily influenced by code from Jörg Kleuver.
 * This class tries to implement almost the complete RFC 2616 on raw fsockopen.
 * @copyright  Christian Schiffler 2009
 * @author     Christian Schiffler <c.schiffler@cyberspectrum.de>
 * @package    Library
 */
class RequestExtended
{
/* 
	Headers implemented:
		general-header
			Transfer-Encoding        ; Section 14.41
			Accept                   ; Section 14.1
		request-header
			Accept-Encoding          ; Section 14.3
			Range                    ; Section 14.35
	Headers not implemented yet:
		general-header 
			Cache-Control            ; Section 14.9
			Connection               ; Section 14.10
			Date                     ; Section 14.18
			Pragma                   ; Section 14.32
			Trailer                  ; Section 14.40
			Upgrade                  ; Section 14.42
			Via                      ; Section 14.45
			Warning                  ; Section 14.46
		request-header
			Accept-Charset           ; Section 14.2
			Accept-Language          ; Section 14.4
			Authorization            ; Section 14.8
			Expect                   ; Section 14.20
			From                     ; Section 14.22
			If-Match                 ; Section 14.24
			If-Modified-Since        ; Section 14.25
			If-None-Match            ; Section 14.26
			If-Range                 ; Section 14.27
			If-Unmodified-Since      ; Section 14.28
			Max-Forwards             ; Section 14.31
			Proxy-Authorization      ; Section 14.34
			Referer                  ; Section 14.36
			TE                       ; Section 14.39
*/


	/**
	 * lookup map to provide error strings.
	 * @var array
	 */
	protected $responses = array
		(
			100 => 'Continue',
			101 => 'Switching Protocols',
			200 => 'OK',
			201 => 'Created',
			202 => 'Accepted',
			203 => 'Non-Authoritative Information',
			204 => 'No Content',
			205 => 'Reset Content',
			206 => 'Partial Content',
			300 => 'Multiple Choices',
			301 => 'Moved Permanently',
			302 => 'Found',
			303 => 'See Other',
			304 => 'Not Modified',
			305 => 'Use Proxy',
			307 => 'Temporary Redirect',
			400 => 'Bad Request',
			401 => 'Unauthorized',
			402 => 'Payment Required',
			403 => 'Forbidden',
			404 => 'Not Found',
			405 => 'Method Not Allowed',
			406 => 'Not Acceptable',
			407 => 'Proxy Authentication Required',
			408 => 'Request Timeout',
			409 => 'Conflict',
			410 => 'Gone',
			411 => 'Length Required',
			412 => 'Precondition Failed',
			413 => 'Request Entity Too Large',
			414 => 'Request-URI Too Large',
			415 => 'Unsupported Media Type',
			416 => 'Requested Range Not Satisfiable',
			417 => 'Expectation Failed',
			500 => 'Internal Server Error',
			501 => 'Not Implemented',
			502 => 'Bad Gateway',
			503 => 'Service Unavailable',
			504 => 'Gateway Timeout',
			505 => 'HTTP Version Not Supported'
		);

	/**
	 * Handle of the current connection.
	 * @var resource
	 */
	protected $socket = NULL;

	/**
	 * URI of the request.
	 * @var array
	 */
	protected $arrUri = array();
	


	/**
	 * Data to be added to the request
	 * @var string
	 */
	protected $strData;
	
	/**
	 * Mime type of sending data. Default is: 'application/octet-stream' (as recommended in RFC 2616 7.2.1).
	 * @var string
	 */
	protected $strDataMime = 'application/octet-stream';
	
	/**
	 * protocol version. Possible values are: '1.1' (default), '1.0'
	 * and '0.9'.
	 * @var string
	 */
	protected $strHttpVersion = '1.1';
	
	/**
	 * If you need to download only a part of the requested document, specify
     * position of subpart start. If 0, then the request will fetch the 
	 * complete document (useful for for broken download restoration, for example.)
	 * @var integer
	 */
	protected $intRangeStart = 0;

	/**
	 * If you need to download only a part of the requested document, specify
     * position of subpart end. If 0, then the request will fetch the 
	 * document from rangeStart to end of document (useful for broken download 
	 * restoration, for example.)
	 * @var integer
	 */
	protected $intRangeEnd = 0;

/*
       Method         = "OPTIONS"                ; Section 9.2
                      | "GET"                    ; Section 9.3
                      | "HEAD"                   ; Section 9.4
                      | "POST"                   ; Section 9.5
                      | "PUT"                    ; Section 9.6
                      | "DELETE"                 ; Section 9.7
                      | "TRACE"                  ; Section 9.8
                      | "CONNECT"                ; Section 9.9
                      | extension-method
       extension-method = token
*/
	/**
	 * Request method (defaults to GET)
	 * @var string
	 */
	protected $strMethod;

	/**
	 * The UserAgent header field - As what do we identify ourselves to the remote Server?
	 * @var string
	 */
	protected $strUserAgent = 'Mozilla/5.0 (compatible; TYPOlight; http://www.typolight.org/) RequestExtended/1.0 (CyberSpectrum RequestExtended; rv:1.0)';


	/**
	 * The media types we accept - Defaults to all media types.
	 * @var string
	 */
	protected $strAccept = '*/*';

	/**
	 * The Encodings we can accept (default: all possible active - Warning, makes debugging of RAW response problematic).
	 * @var array
	 */
	protected $arrAcceptEncoding=array
								(
									'chunked' => 1, 
									// Must not be specified according to RFC in responses, not sure about requests though.
									'identity' => 0, 
									'gzip' => 1,
									// Unimplemented: See Notes in ::decodeCompress() 
									// 'compress' => 1,
									'deflate' => 1
								);
								
	/**
	 * The Transfer-Encoding we want to use for remote requests.
	 * @var string
	 */
	protected $strUseTransferEncoding='chunked';

	/**
	 * The Content-Encoding we want to use for remote requests.
	 * @var string
	 */
	protected $strUseContentEncoding='';

	/**
	 * Error string
	 * @var string
	 */
	protected $strError;

	/**
	 * Response code
	 * @var integer
	 */
	protected $intCode;

	/**
	 * RAW unprocessed Response Headers
	 * @var string
	 */
	protected $strHeaders;

	/**
	 * Response string
	 * @var string
	 */
	protected $strResponse;
	
	/**
	 * RAW unprocessed Response string
	 * @var string
	 */
	protected $strRawResponse;
	
	/**
	 * Request string
	 * @var string
	 */
	protected $strRequest;

	/**
	 * Headers array (these headers will be sent)
	 * @var array
	 */
	protected $arrHeaders = array();
	
	/**
	 * Cookies array (these Cookies will be sent)
	 * @var array
	 */
	protected $arrCookies = array();

	/**
	 * Response headers array (these headers are returned)
	 * @var array
	 */
	protected $arrResponseHeaders = array();

	/**
	 * Proxy settings
	 * @var array
	 */
	protected $arrProxy = array
	(
		'proxyhost'    => '',
		'proxyport'    => 8080,
		'proxyuser'    => '',
		'proxypass'    => ''
	);

	/**
	 * Set default values
	 */
	public function __construct()
	{
		$this->strData = '';
		$this->strMethod = 'get';
	}


	/**
	 * Set an object property
	 * @param string
	 * @param mixed
	 * @throws Exception
	 */
	public function __set($strKey, $varValue)
	{
		switch ($strKey)
		{
			case 'data':
				$this->strData = $varValue;
				break;

			case 'datamime':
				$this->strDataMime = $varValue;
				break;

			case 'version':
				$this->strHttpVersion = $varValue;
				break;

			case 'rangestart':
				$this->strDataMime = $varValue;
				break;

			case 'rangeend':
				$this->strDataMime = $varValue;
				break;

			case 'method':
				$this->strMethod = $varValue;
				break;
			
			case 'useragent':
				$this->strUserAgent = $varValue;
				break;
				
			case 'acceptmime':
				$this->strAccept = $varValue;
				break;
				
			case 'acceptgzip':
				$this->arrAcceptEncoding['gzip'] = $varValue;
				break;
				
			case 'acceptdeflate':
				$this->arrAcceptEncoding['deflate'] = $varValue;
				break;

			// TODO: encoding for sending is not working yet.
			case 'usetransferencoding':
				//$this->strUseTransferEncoding = $varValue;
				break;

			// TODO: encoding for sending is not working yet.
			case 'usecontentencoding':
				//$this->strUseContentEncoding = $varValue;
				break;

			case 'proxyhost':
			case 'proxyport':
			case 'proxyuser':
			case 'proxypass':
				$this->arrProxy[$strKey] = $varValue;
				break;

			default:
				throw new Exception(sprintf('Invalid argument "%s"', $strKey));
				break;
		}
	}


	/**
	 * Return an object property
	 * @param string
	 * @return mixed
	 */
	public function __get($strKey)
	{
		switch ($strKey)
		{
			case 'error':
				return $this->strError;
				break;

			case 'code':
				return $this->intCode;
				break;

			case 'request':
				return $this->strRequest;
				break;

			case 'response':
				return $this->strResponse;
				break;

			case 'rawresponse':
				return $this->strRawResponse;
				break;

			case 'headers':
				return $this->arrResponseHeaders;
				break;

			case 'cookies':
				return $this->arrCookies;
				break;

			default:
				return null;
				break;
		}
	}
	
	/**
	 * Set additional request headers
	 * @param string
	 * @param mixed
	 */
	public function setHeader($strKey, $varValue)
	{
		$this->arrHeaders[$strKey] = $varValue;
	}

	/**
	 * Return true if there has been an error
	 * @return boolean
	 */
	public function hasError()
	{
		return strlen($this->strError) ? true : false;
	}

	/**
	 * Check if a string contains a valid IPv6 address.
	 * @param string
	 * @return boolean
	 */
	protected function isIP6($string)
	{
		return (filter_var($string, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? true : false);
	}
	
	/**
	 * decode a "Transfer-Encoding: chunked" encoded reply.
	 * @param string
	 * @return string
	 */
	protected function decodeChunked($string)
	{
		$lines = explode("\r\n",$string);
		$i=0;
		$length = 999;
		$content = '';
		foreach($lines as $line) {
			$i++;
			if ($i%2 == 1) {
				$length = hexdec($line);
			} elseif ($length == strlen($line)) {
			$content .= $line;
		}
			if ($length == 0)
				break;
		}
		return $content;
	}

	/**
	 * decode a "gzip" encoded reply.
	 * @param string
	 * @return string
	 */
	protected function decodeGzip($string){
		// check for valid header and return input data if no valid magic number found.
		if((ord($string[0]) != 0x1f) || (ord($string[1]) != 0x8b))
		{
			return $string;
		}
		// Remove the magic bytes, the filetime etc. to have a plain gzipped data.
		$try = substr($string, 10);
		$try = @gzinflate($try);
		if(strlen($try))
			return $try;
		// giving up :(
		return $string;
	}

	/**
	 * decode a "deflate" encoded reply.
	 * @param string
	 * @return string
	 */
	protected function decodeDeflate($string){
		$try = @gzuncompress($string);
		if(strlen($try))
			return $try;
		// It turns out that some browsers expect deflated data without the 
		// first two bytes (a kind of header) and and the last four bytes (an ADLER32 checksum).
		// IIS 5 also requires gzinflate instead of gzuncompress (similar to 
		// IE 5 and gzdeflate v. gzcompress) this means there are no Zlib headers, although 
		// there should be. We try to uncompress in the IE way now.
		$try = substr($string, 1, -4);
		$try = @gzinflate($string);		
		if(strlen($try))
			return $try;
		// if we did still not succeed, fall back to gzip as last resort.
		$try = $this->decodeGzip($string);
		if(strlen($try))
			return $try;
		// Nothing worked out, giving up now. :(
		return $string;
	}
	
	/**
	 * decode a "compress" encoded reply.
	 * currently unimplemented idea can come from 
	 * http://whoyouknow.co.uk/uni/datacompression/lzw.php?source	<- demo implementation on bitstrings
	 * http://www.geocities.com/yccheok/lzw/lzw.html				<- doc of algorithm
	 * http://wiki.lmu-mi.de/index.php/LZW-Kodierung				<- german
	 * @param string
	 * @return string
	 */
	protected function decodeCompress($string){
		// TODO: unimplemented.
		return $string;
	}

	/**
	 * decode the response using the given algorithm.
	 * @param string
	 */
	protected function decodeResponse($algorithm)
	{
		if($algorithm == 'chunked')
			$this->strResponse = $this->decodeChunked($this->strResponse);
		if($algorithm == 'gzip' || $algorithm == 'x-gzip')
			$this->strResponse = $this->decodeGzip($this->strResponse);
		if($algorithm == 'deflate')
			$this->strResponse = $this->decodeDeflate($this->strResponse);
	}


	protected function encodeGzip(&$strData)
	{
		$gzip_contents = gzcompress($strData, 1);
		return $gzip_contents;
		$gzip_size = strlen($strData);
		$gzip_crc = crc32($strData);
		$gzip_contents = gzcompress($strData, 9);
		$gzip_contents = substr($gzip_contents, 0, -4);
		// return magic-number + header(filedate etc.) + crc + size
		return "\x1f\x8b\x08\x00\x00\x00\x00\x00" . $gzip_contents . pack('V', $gzip_crc) . pack('V', $gzip_size);
	}

	protected function encodeDeflate(&$strData)
	{
		$gzip_contents = gzencode($strData, 1);
		return $gzip_contents;
	}

	/**
	 * encode the given data using the given algorithm.
	 * @param ref-string (will get altered)
	 * @param string
	 */
	protected function encodeData(&$strData, $algorithm)
	{
		switch($algorithm)
		{
			case 'chunked':
				return false;
			case 'gzip':
				$strData=$this->encodeGzip($strData);
				return true;
			case 'deflate':
				$strData=$this->encodeDeflate($strData);
				return true;
			case 'compress':
			default:
				return false;
		}
	}

	protected function encodeRequest(&$strData)
	{
		// first apply ContentEncoding, then TransferEncoding.
		// Add header to request headers if necessary.
		if($this->encodeData($strData, $this->strUseContentEncoding))
			$this->setHeader('Content-Encoding', $this->strUseContentEncoding);
		if($this->encodeData($strData, $this->strUseTransferEncoding))
			$this->setHeader('Transfer-Encoding', $this->strUseTransferEncoding);
		return $strData;
	}

	protected function openSocket($host, $port)
	{
		$this->socket = @fsockopen($host, $port, $errno, $errstr, 10);
		if (!is_resource($this->socket))
		{
			$this->intCode = $errno;
			$this->strError = trim($errno .' '. $errstr);
			return false;
		}
		return $this->socket;
	}

	/**
	 * Connect to the webserver defined in the URI.
	 * @return boolean
	 */
	protected function connect()
	{
		switch ($this->arrUri['scheme'])
		{
			case 'http':
				if(!isset($this->arrUri['port']))
					$this->arrUri['port']=80;
				$this->arrUri['addport'] = ($this->arrUri['port'] != 80);
				$host=$this->arrUri['host'];
				$port=$this->arrUri['port'];
				break;
			case 'https':
				if(!isset($this->arrUri['port']))
					$this->arrUri['port']=443;
				$this->arrUri['addport'] = ($this->arrUri['port'] != 443);
				$host='ssl://' . $this->arrUri['host'];
				$port=$this->arrUri['port'];
				break;
			default:
				$this->intCode = -1;
				$this->strError = 'Invalid schema ' . $this->arrUri['scheme'];
				return false;
				break;
		}
		// Do we want to connect via a proxy or directly?
		if ($this->arrProxy['proxyhost'])
		{
			// connect via proxy.
			$this->socket = $this->openSocket($this->arrProxy['proxyhost'], $this->arrProxy['proxyport']);
			// proxy-auth
			if ($this->arrProxy['proxyuser'] && !isset($this->arrHeaders['Proxy-Authorization']))
			{
				$this->arrHeaders['Proxy-Authorization'] = 'Basic '.base64_encode ($this->arrProxy['proxyuser'] . ':' . $this->arrProxy['proxypass']);
			}
			// perform CONNECT with the proxy if https
			if ($this->arrUri['scheme'] == 'https') {
				try 
				{
					$request = sprintf('CONNECT %s:%s HTTP/1.1%sHost: %s%s', $host, $port, "\r\n", $this->arrProxy['proxyhost'], "\r\n");
					if (isset($strUserAgent['User-Agent']))
						$request .= 'User-Agent: ' . $this->strUserAgent . "\r\n";
					// If the proxy-authorization header is set, send it to proxy but remove it from headers sent to target host
					if (isset($this->arrHeaders['Proxy-Authorization'])) {
						$request .= 'Proxy-Authorization: ' . $this->arrHeaders['Proxy-Authorization'] . "\r\n";
						unset($this->arrHeaders['Proxy-Authorization']);
					}
					$request .= "\r\n";
					// Send the request
					if (!@fwrite($this->socket, $request))
					{
						throw new Exception("Error writing request to proxy server");
					}
					// Read response headers only
					$response = '';
					$gotStatus = false;
					while ($line = @fgets($this->socket))
					{
						$gotStatus = $gotStatus || (strpos($line, 'HTTP') !== false);
						if ($gotStatus)
						{
							$response .= $line;
							if(!chop($line))break;
						}
					}
					// Check that the response from the proxy is 200
					if (substr($response, 9, 3) != 200) {
						throw new Exception("Unable to connect to HTTPS proxy. Server response: " . $response);
					}
					// If all is good, switch socket to secure mode. We have to fall back through the different modes 
					$success = false; 
					foreach(array(STREAM_CRYPTO_METHOD_TLS_CLIENT, STREAM_CRYPTO_METHOD_SSLv3_CLIENT, 
								  STREAM_CRYPTO_METHOD_SSLv23_CLIENT,STREAM_CRYPTO_METHOD_SSLv2_CLIENT) as $mode)
					{
						if ($success=stream_socket_enable_crypto($this->socket, true, $mode)) break;
					}
					if (!$success)
					{
						throw new Exception("Unable to connect to HTTPS server through proxy: could not negotiate secure connection.");
					}
				}
				catch (Exception $e)
				{
					// Close socket
					$this->disconnect();
					$this->strError = $e->getMessage();
				}
			}
		} else {
			// no proxy needed
			$this->socket = $this->openSocket($host, $port);
		}
		return (is_resource($this->socket)) ? true : false;
	}

	/**
	 * Disconnect from the webserver.
	 */
	protected function disconnect()
	{
		if(is_resource($this->socket))
		{
			fclose($this->socket);
			$this->socket=NULL;
		}
	}
	
	/**
	 * send the prepared request to the connection if any is present.
	 */
	protected function sendRequest()
	{
		if(is_resource($this->socket))
		{
			fwrite($this->socket, $this->strRequest);
		}
	}
	
	/**
	 * reads the response until eof or content length reached.
	 */
	protected function readResponse()
	{
		$this->strRawResponse='';
		if(is_resource($this->socket))
		{
			/*
				TODO: Shall we implement a timeout within here to detect if a server let's us die slowly? 
				Can we? 
				Would be nice to have to prevent issues like we already had with twitter reader which brought 
				whole TL installations down when twitter WebService was down.
			*/
			$data = '';
			// read header.
			while (!feof($this->socket) && ($chunk = fread($this->socket, 1024)) != false)
			{
				// TODO: add inline check for "Content-Length: xxx" and stop reading after that - needed for multiple connections.
				$data .= $chunk;
				$this->strRawResponse.=$chunk;
				// strip 100 header if present.
				$pos=strpos($data, "HTTP/1.1 100\r\n");
				if($pos > 1)
				{
					$data = substr($data, $pos+12);
				}
				// end of headers contained?
				$pos=strpos($data, "\r\n\r\n");
				if($pos > 1)
				{
					$headers = substr($data, 0, $pos);
					$response = substr($data, $pos+4);
				}
			}
			// read response.
			$data = '';
			while (!feof($this->socket) && ($chunk = fread($this->socket, 1024)) != false)
			{
				$response .= $chunk;
			}
			$this->strResponse=$response;
			$this->strHeaders=$headers;
		}
	}

	/**
	 * Compile the arrUri to an URL again
	 */
	protected function combineUri()
	{
		return	(isset($this->arrUri['scheme'])?$this->arrUri['scheme'].'://':'').
				(isset($this->arrUri['user'])?$this->arrUri['user'].':':'').
				(isset($this->arrUri['pass'])?$this->arrUri['pass'].'@':'').
				(isset($this->arrUri['host'])?$this->arrUri['host']:'').
				(isset($this->arrUri['port'])?':'.$this->arrUri['port']:'').
				(isset($this->arrUri['path'])?$this->arrUri['path']:'').
				(isset($this->arrUri['query'])?'?'.$this->arrUri['query']:'').
				(isset($this->arrUri['fragment'])?'#'.$this->arrUri['fragment']:'');
	}

	/**
	 * Prepares the complete request data. Method, add headers and add POST data (if any).
	 * @param string
	 */
	protected function prepareRequest()
	{
		// if no path defined, we check if we are performing an "OPTIONS" request, if so we want to get the server OPTIONS, use the root "/" otherwise.
		$this->arrUri['fullpath'] = isset($this->arrUri['path']) ? $this->arrUri['path'] : ($this->strMethod == 'OPTIONS' ? '*' : '/');

		if (isset($this->arrUri['query']))
		{
			// remove any ampersand as we can not use it in a valid HTTP Query.
			$this->arrUri['fullpath'] .= '?' . str_replace('&amp;', '&', $this->arrUri['query']);
		}
		if ($this->arrProxy['proxyhost'] && $this->arrUri['scheme'] != 'https')
			$request = strtoupper($this->strMethod) .' '. $this->combineUri() .' HTTP/' . $this->strHttpVersion . "\r\n";
		else
			$request = strtoupper($this->strMethod) .' '. $this->arrUri['fullpath'] .' HTTP/' . $this->strHttpVersion . "\r\n";
		$request .= implode("\r\n", $this->compileHeaders());
		$request .= "\r\n\r\n";

		// A message-body MUST NOT be included in a request if the specification of the request 
		// method (section 5.1.1) does not allow sending an entity-body in requests.
		// TODO: determine if the request does allow a message body and clean it if it does not (or rather return false immediately?).
		if (strlen($this->strData))
		{
			$request .= $this->encodeRequest($this->strData) . "\r\n";
		}
		$this->strRequest=$request;
	}
	
	/**
	 * parse a cookie header line and add the cookie to the list.
	 * @param string
	 */
	protected function parseCookie($line)
	{
		$csplit = explode(';', $line);
		$cdata = array();
		foreach( $csplit as $data ) {
			$cinfo = explode('=', $data, 2);
			$cinfo[0] = trim( $cinfo[0] );
			if( $cinfo[0] == 'expires' ) $cinfo[1] = strtotime( $cinfo[1] );
			if( $cinfo[0] == 'secure' ) $cinfo[1] = "true";
			if( in_array( $cinfo[0], array( 'domain', 'expires', 'path', 'secure', 'comment', 'version' ) ) ) {
				$cdata[trim( $cinfo[0] )] = $cinfo[1];
			}
			else {
				$cdata['name'] = $cinfo[0];
				$cdata['value'] = $cinfo[1];
			}
		}
		if(!$this->checkCookie($cdata))
			return;
		$this->arrCookies[$cdata['name']]=$cdata;
	}
	
	/**
	 * matches the cookie against the current request parameters and returns the result.
	 * @param array
	 * @return array
	 */
	protected function checkCookie($cookie=array())
	{
		// TODO: add further checks here.
		// cookie expired - REJECT!
		if(isset($cookie['expires']) && ($cookie['expires'] < time()))
			return false;
		// host is not matching - REJECT!
		if(!strstr($this->arrUri['host'], $cookie['domain']))
			return false;
		// path is not matching - REJECT!
		if(!strstr($this->arrUri['fullpath'], $cookie['path']))
			return false;
		// cookie is valid
		return true;
	}
	
	/**
	 * compile cookies and return as array of strings.
	 * @return array
	 */
	protected function compileCookies()
	{
		$ret=array();
		foreach($this->arrCookies as $name=>$cookie)
		{
			if(!$this->checkCookie($cookie))
			{
				continue;
			}
			$tmp='Cookie: '.$cookie['name'].'='.$cookie['value'] . '; $version='.(isset($cookie['version']) ? $cookie['version'] : '1');
			foreach($cookie as $key=>$value)
				if(!in_array($key, array('name', 'value', 'version')))
					$tmp .= '; $' . $key . '=' . $value;
			$ret[] = $tmp;
		}
		return $ret;
	}
	
	/**
	 * compile headers and return as array of strings.
	 * @return array
	 */
	protected function compileHeaders()
	{
		if ($this->arrProxy['proxyhost'] && $this->arrUri['scheme'] != 'https')
			$headers = array('Host' => 'Host: ' . ($this->isIP6($this->arrUri['host']) ? '[' . $this->arrUri['host'] . ']' : $this->arrUri['host']) . ($this->arrUri['addport'] ? ':' . $this->arrUri['port'] : ''));
		else
			$headers = array();
		$headers['User-Agent'] = 'User-Agent: ' . $this->strUserAgent;
		// TODO: do we want to add support for keep-alive?
		$headers['Connection'] = 'Connection: close';

		$encodings=array();
		foreach($this->arrAcceptEncoding as $name=>$enabled)
		{
			$encodings[] = $name . ';q=' . (!$enabled ? '0' : $enabled);
		}
		$headers['Accept-Encoding'] = 'Accept-Encoding: ' . join(',', $encodings);
		
		if(strlen($this->strAccept))
		{
			$headers['Accept'] = 'Accept: ' . $this->strAccept;
		}
		
		if($this->strData)
		{
			$headers['Content-Length'] = 'Content-Length: ' . strlen($this->strData);
			if(strlen($this->strDataMime))
				$headers['Content-Type'] = 'Content-Type: ' . $this->strDataMime;
		}

		// setting Ranges
		if(($this->intRangeStart > 0) || ($this->intRangeEnd > 0))
		{
			$headers['Range'] ='Range: bytes=' . $this->intRangeStart . '-' . (($this->intRangeEnd >= $this->intRangeStart) ? $this->intRangeEnd : '');
		}
		
		// add cookies.
		foreach ($this->compileCookies() as $cookie)
			$headers[] = $cookie;

		// add user headers.
		foreach ($this->arrHeaders as $header=>$value)
		{
			$headers[$header] = $header . ': ' . $value;
		}
		return $headers;
	}

	
	/**
	 * parse a header line.
	 * @param string
	 * @param string
	 */
	protected function processHeaderLine($header, $value)
	{
		if($header == 'Set-Cookie')
		{
			$this->parseCookie($value);
		} else {
			$this->arrResponseHeaders[$header] = trim($value);
		}
	}

	/**
	 * parse a HTTP response.
	 * @param string
	 * @param string
	 */
	protected function parseHeader()
	{
		$split = preg_split("/\r\n|\n|\r/", $this->strHeaders);
		$this->arrResponseHeaders = array();
		list(, $code, $text) = explode(' ', trim(array_shift($split)), 3);
		$header='';
		$cookies=array();
		while (($line = trim(array_shift($split))) != false)
		{
			// Headers can wrap over multiple lines. Therefore we collect everything together 
			// until the next field begins.
			// check if this is a new header field.
			if(preg_match('#^[a-zA-Z0-9\-]+:#U', $line))
			{
				if(strlen($header))
				{
					$this->processHeaderLine($header, trim($value));
				}
				list($header, $value) = explode(':', $line, 2);
			} else {
				$value .= ' ' . $line;
			}
		}
		if(strlen($header) && strlen($value))
		{
			$this->processHeaderLine($header, trim($value));
		}
		if(array_key_exists('Transfer-Encoding', $this->arrResponseHeaders) && $this->arrResponseHeaders['Transfer-Encoding'])
			$this->decodeResponse($this->arrResponseHeaders['Transfer-Encoding']);
		if(array_key_exists('Content-Encoding', $this->arrResponseHeaders) && $this->arrResponseHeaders['Content-Encoding'])
			$this->decodeResponse($this->arrResponseHeaders['Content-Encoding']);
		
		$this->intCode = $code;
		// TODO: is it really wise to fallback to the next generic error message?
		if (!isset($responses[$code]))
		{
			$code = floor($code / 100) * 100;
		}

		// TODO: handle special error codes like "301/302 moved", ... here.
		if (!in_array(intval($code), array(200, 304)))
		{
			$this->strError = strlen($text) ? $text : $this->responses[$code];
		}
	}

	/**
	 * Perform an HTTP request (handle GET, POST, PUT and any other HTTP request)
	 * @param string
	 * @param string
	 * @param string
	 */
	public function send($strUrl, $strData=false, $strMethod=false)
	{
		// A message-body MUST NOT be included in a request if the specification of the request 
		// method (section 5.1.1) does not allow sending an entity-body in requests.
		// TODO: determine if the request does allow a message body and clean it if it does not (or rather return false immediately?).
		if ($strData)
		{
			$this->strData = $strData;
		}

		if ($strMethod)
		{
			$this->strMethod = $strMethod;
		}

		$errstr = '';
		$errno = null;
		$this->arrUri = parse_url($strUrl);
		if(!$this->connect())
			return false;
		$this->prepareRequest();
		$this->sendRequest();
		$this->readResponse();
		$this->parseHeader();
		// new functionality.
		$headers = '';
		$response = '';
		$data = '';
		// TODO: have to alter here when not using Connection: close - keep this in mind.
		$this->disconnect();
		return !$this->hasError();
	}
	
	/**
	 * Perform an HTTP GET request (url encoded form data).
	 * @param string
	 * @param array
	 */
	public function getUrlEncoded($strUrl, $arrData=array())
	{
		$this->strDataMime = NULL;
		if(is_array($arrData))
		{
			$urlEncodedData=array();
			foreach($arrData as $key=>$value)
				$urlEncodedData[] = $key . '=' . urlencode($value);
			$data=join('&', $urlEncodedData);
		} else {
			$data = $arrData;
		}
		if(strlen($data))
		{
			if(strpos($strUrl, '?'))
			{
				$strUrl .= '&' . $data;
			} else {
				$strUrl .= '?' . $data;
			}
		}
		return $this->send($strUrl , NULL, 'GET');
	}

	/**
	 * Perform an HTTP POST request (url encoded form data).
	 * @param string
	 * @param array
	 */
	public function postUrlEncoded($strUrl, $arrData=array())
	{
		$this->strDataMime = 'application/x-www-form-urlencoded';
		$urlEncodedData=array();
		foreach($arrData as $key=>$value)
			$urlEncodedData[] = $key . '=' . urlencode($value);
		
		return $this->send($strUrl, join('&', $urlEncodedData), 'POST');
	}

	/**
	 * Perform an HTTP POST request (url encoded form data).
	 * @param string
	 * @param MultipartFormdata
	 */
	public function postMultipartFormdata($strUrl, $objData=NULL)
	{
		if(!($objData instanceof MultipartFormdata))
		{
			if(is_array($objData))
			{
				$tmp=new MultipartFormdata();
				foreach($objData as $key=>$value)
					$tmp->setField($key, $value);
				$objData=$tmp;
			} else {
				// What shall we do if no name => value pair is found?
				// I think we should handle this better.
				return false;
			}
		}
		$this->strDataMime = $objData->getContentTypeHeader();
		$data= $objData->compile();
		return $this->send($strUrl, $objData->compile(), 'POST');
	}
}

?>