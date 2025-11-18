<?php
unset($CFG);
global $CFG;
$CFG = new stdClass();

$CFG->wwwroot   = 'http://test-service-with-obsolete-moodle:80';
$CFG->dirroot   = '/var/www/html';
$CFG->dataroot  = '/var/www/moodledata';

$CFG->dbtype    = 'mysqli';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'test-db-for-obsolete-moodle';
$CFG->dbuser    = 'moodle';
$CFG->dbpass    = 'password';
$CFG->dbname    = 'moodle';
$CFG->prefix    = 'mdl_';

require_once(__DIR__ . '/lib/setup.php');
