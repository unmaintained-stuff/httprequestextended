<?php

/**
 * PHP version 5
 * @copyright	CyberSpectrum 2011
 * @author		Christian Schiffler <c.schiffler@cyberspectrum.de>
 * @package		RequestExtended
 * @license		LGPL
 * @filesource
 */

// contao 2.x
$GLOBALS['TL_CACHE']['requests'] = 'tl_requestcache';

// contao 3.x
$GLOBALS['TL_PURGE']['tables']['httprequestextended'] = array(
	'callback' => array('RequestPruner', 'purgeRequestCache'),
	'affected' => array('tl_requestcache'),
);

/**
 * Cron jobs
 */
$GLOBALS['TL_CRON']['daily'][]  = array('RequestPruner', 'prune');

