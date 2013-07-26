<?php

/**
 * Contao Open Source CMS
 *
 * Copyright (c) 2005-2013 Leo Feyer
 *
 * @package Httprequestextended
 * @link    https://contao.org
 * @license http://www.gnu.org/licenses/lgpl-3.0.html LGPL
 */


/**
 * Register the classes
 */
ClassLoader::addClasses(array
(
	'MultipartFormdata'     => 'system/modules/httprequestextended/MultipartFormdata.php',
	'RequestExtended'       => 'system/modules/httprequestextended/RequestExtended.php',
	'RequestExtendedCached' => 'system/modules/httprequestextended/RequestExtendedCached.php',
	'RequestPruner'         => 'system/modules/httprequestextended/RequestPruner.php',
));
