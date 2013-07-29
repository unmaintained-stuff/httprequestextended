<?php

/**
 * PHP version 5
 * @copyright	Christian Schiffler <c.schiffler@cyberspectrum.de>
 * @package		RequestExtended
 * @license		LGPL 
 * @filesource
 */

/**
 * Class Request11
 *
 * Extend RequestExtended with cached request functionality.
 * @copyright  Christian Schiffler 2011
 * @author     Christian Schiffler <c.schiffler@cyberspectrum.de>
 * @package    Library
 */
class RequestExtendedCached extends \RequestExtended
{
	protected $Database = NULL;

	protected $intCacheTime = 3600;

	protected $noCache = false;

	/**
	 * Set default values
	 */
	public function __construct($intCacheTime=3600)
	{
		$this->Database=\Database::getInstance();
		$this->intCacheTime = $intCacheTime;
		parent::__construct();
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
			case 'cacheTime':
				$this->intCacheTime = $varValue;
				break;
			case 'noCache':
				$this->noCache = $varValue;
				break;
			default:
				parent::__set($strKey, $varValue);
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
			case 'cacheTime':
				return $this->intCacheTime;
				break;
			case 'noCache':
				return $this->noCache;
				break;
			default:
				return parent::__get($strKey);
				break;
		}
	}

	protected function putCache()
	{
		// put to cache
		$data=array(
					'hashkey'=> $this->getCacheKey(),
					'tstamp' => time()+$this->intCacheTime,
					'data' => $this->strResponse,
					'header' => $this->strHeaders
					);
		$this->Database->prepare('INSERT INTO tl_requestcache %s')->set($data)->execute();
	}

	protected function getCacheKey()
	{
		return md5($this->strRequest);
	}

	/*
	 * Performs the request but checks in cache first if the request has already been executed in the past.
	 * If it has been executed, we use the infor from then.
	 *
	 */
	protected function performRequest()
	{
		// clean responses.
		$this->intCode=0;
		$this->strError='';
		$this->strResponseHeaders=NULL;
		$this->strResponse=NULL;
		$this->arrResponseHeaders=NULL;
		$this->prepareRequest();
		// check if data is present in cache.
		if(!$this->noCache)
			$objResponse=$this->Database->prepare('SELECT * FROM tl_requestcache WHERE hashkey=? AND tstamp>?')->execute($this->getCacheKey(), time());
		if($this->noCache || (!$objResponse->next()))
		{
			parent::performRequest();
			if((!$this->noCache) && ($this->intCode==200 || $this->intCode==207))
			{
				$this->putCache();
			}
		} else {
			$this->strResponse = $objResponse->data;
			$this->strResponseHeaders = $objResponse->header;
			$this->intCode=200;
		}
	}
}
