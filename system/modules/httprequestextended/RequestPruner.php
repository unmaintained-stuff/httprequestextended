<?php

/**
 * PHP version 5
 * @copyright	Christian Schiffler <c.schiffler@cyberspectrum.de>
 * @package		RequestExtended
 * @license		LGPL
 * @filesource
 */

/**
 * Class RequestPruner
 *
 * @copyright	CyberSpectrum 2011
 * @author		Christian Schiffler <c.schiffler@cyberspectrum.de>
 * @package		Controller
 *
 */
class RequestPruner extends \System
{
	public function prune()
	{
		$time = time();
		Database::getInstance()->prepare('DELETE FROM tl_requestcache WHERE tstamp<?')->execute($time);
		$this->log('Pruned the request cache of requests older than ' . $time, __METHOD__, TL_CRON);
	}

	public function purgeRequestCache()
	{
		Database::getInstance()->execute('TRUNCATE TABLE tl_requestcache');
		$this->log('Purged the request cache', __METHOD__, TL_CRON);
	}

}
