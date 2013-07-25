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
	'RequestExtendedCached' => 'system/modules/httprequestextended/RequestExtendedCached.php',
	'MultipartFormdata'     => 'system/modules/httprequestextended/MultipartFormdata.php',
	'RequestExtended'       => 'system/modules/httprequestextended/RequestExtended.php',
	'RequestPruner'         => 'system/modules/httprequestextended/RequestPruner.php',
));
