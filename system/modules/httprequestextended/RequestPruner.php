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
		$this->import('Database');
		$this->Database->prepare('DELETE FROM tl_requestcache WHERE tstamp<?')->execute(time());
	}
};
