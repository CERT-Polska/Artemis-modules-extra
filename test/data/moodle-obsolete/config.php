<?php
unset($CFG);
global $CFG;
$CFG = new stdClass();

$CFG->wwwroot   = 'http://localhost:8080';
$CFG->dirroot   = '/var/www/html';
$CFG->dataroot  = '/var/www/moodledata';

$CFG->dbtype    = 'sqlite3';
$CFG->dblibrary = 'native';
$CFG->dbname    = 'moodle';
$CFG->prefix    = 'mdl_';

$CFG->directorypermissions = 0777;

require_once(__DIR__ . '/lib/setup.php');
