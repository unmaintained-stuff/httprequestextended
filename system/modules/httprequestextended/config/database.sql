-- **********************************************************
-- *                                                        *
-- * IMPORTANT NOTE                                         *
-- *                                                        *
-- * Do not import this file manually but use the Contao    *
-- * install tool to create and maintain database tables!   *
-- *                                                        *
-- **********************************************************

-- --------------------------------------------------------

CREATE TABLE `tl_requestcache` (
  `id` int(10) unsigned NOT NULL auto_increment,  
  `hashkey` varchar(255) NOT NULL default '',
  `tstamp` int(10) unsigned NOT NULL default '0',
  `data` mediumblob NULL
  `header` mediumblob NULL
  PRIMARY KEY  (`id`), 
  KEY `tstamp` (`tstamp`),
  KEY `hashkey` (`hashkey`) 
) ENGINE=MyISAM DEFAULT CHARSET=utf8;