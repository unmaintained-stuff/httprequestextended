<?php if (!defined('TL_ROOT')) die('You can not access this file directly!');

/**
 * PHP version 5
 * @copyright	CyberSpectrum 2011
 * @author		Christian Schiffler <c.schiffler@cyberspectrum.de>
 * @package		RequestExtended
 * @license		LGPL 
 * @filesource
 */

$GLOBALS['TL_CACHE']['requests']='tl_requestcache';

/**
 * Cron jobs
 */
$GLOBALS['TL_CRON']['daily'][]  = array('RequestPruner', 'prune');

?>