#!/usr/bin/env python

import auparse
import audit
import configparser
import logging
import os
import sys
import time

#
# Lets define somce fun functions!
#


def validatesections(sectionname):
    "Validate the different config file sections for required items"
    defaultrequired=[]
    defaultoptionals=['logfile','logleve']
    sectionrequired=['keyname','action','chroot']
    sectionoptionals=['destination','uid']
    if sectionname.upper() != 'DEFAULT':

        logging.info('Checking ' + sectionname.upper() + ' for required keys.')
        for keycheck in sectionrequired:
            if not cfg[sectionname][keycheck]:
                logging.critical('CRTICAL ERROR: Missing ' + keycheck + ' in section ' + secetionname.upper() + '.')
                sys.exit(2)

        logging.info('Checking ' + sectionname.upper() + ' for optional keys.')
        for keycheck in sectionoptionals:
            if not cfg[sectionname][keycheck]:
                logging.warning('WARNING: Missing ' + keycheck + ' in section ' + secetionname.upper() + '.')

        if not cfg[sectionname]['destination'] and cfg[sectionname][action] != 'rm':
                logging.warning('WARNING: No destination is defined, but the action is not rm.')


def cleanuppaths(chroot,targetfilepath,targetfilename):
    "Cleanup and validate targetfilepath"
    if targetfilepath.startswith(chroot) and targetfilepath.endswith(targetfilename):
        if os.path.exists(targetfilepath) and os.path.isfile(targetfilepath):
                return targetfilepath
    else:
        targetfullpath = os.path.join(chroot, targetfilename)
        if not os.path.exists(targetfullpath):
            logging.error('ERROR: The combined path does not exist: ' + targetfullpath)
        return targetfullpath

#
# Read the configfile
#

configfile='/etc/filewatcher.ini'

cfg = configparser.ConfigParser()
cfg.read(configfile)

#
# Setup Logging
#

logfile = '/var/log/filewatcher.log'
loglevel = 'debug'

#if cfg['default']['logfile']:
if cfg.get('default', 'logfile'):
    logfile = cfg['default']['logfile']

#if cfg['default']['loglevel']:
if cfg.get('default', 'loglevel'):
    loglevel = cfg['default']['loglevel']

logging.basicConfig(filename=logfile, level=loglevel.upper())

logging.info('Filewatcher starting...')

#
# Build an index to check and validate we have specific keys
#
logging.info('Building section index...')

cfgsections=cfg.sections()
cfgkeys=[]

if 'default' in cfgsections:
    cfgsections.remove('default')

logging.debug('Current list of configuration sections from INI: ' + str(cfgsections))

logging.info('Building key index')
for name in cfgsections:
    cfgkeys.append({cfg.get(name, 'keyname'):name})
    validatesections(name)

logging.debug('Current list of key index: ' + str(cfgkeys))


logging.info('Opening Auditd source')

aup = auparse.AuParser(auparse.AUSOURCE_DESCRIPTOR, 0);

while not aup.first_record():
    logging.debug('Snoozing until first event')
    time.sleep(10)

logging.info('Entering main loop')
while True:
    #Ensure we are at the first event record and the first field
    aup.first_record()
    aup.first_field()
    mytype = aup.get_type_name()
    logging.debug(mytype + ' is the first record type')
    key = aup.find_field('key')
    logging.debug(key + ' is the first found key')

    # Check to see if we expect an event with this key
    logging.info('Checking if key is in the list...')
    logging.debug('Current keys are ' + str(cfgkeys))
    logging.debug('Current key is ' + key)
    if key in cfgkeys:
        logging.info('Found the key ' + key + 'in the list.')
        # reset to first record
        aup.first_record()
        while True:
            logging.info('looping over event records')
            # Loop over the different records for data we want
            aup.first_field()
            mytype = aup.get_type_name()
            fieldname = aup.get_field_name()
            while True:
                if mytype == 'PATH':
                    logging.debug('Looping over ' + mytype + ' record type')
                    while fieldname != 'name':
                        aup.next_field
                        fieldname = aup.get_field_name()
                    targetfilename = aup.get_field_str()
                elif mytype == 'CWD':
                    logging.debug('Looping over ' + mytype + ' record type')
                    while fieldname != 'cwd':
                        aup.next_field
                        fieldname = aup.get_field_name()
                    targetfilepath = aup.get_field_str()
                elif mytype == 'SYSCALL':
                    logging.debug('Looping over ' + mytype + ' record type')
                    while fieldname != 'uid':
                        aup.next_field
                        fieldname = aup.get_field_name()
                    targetuid = aup.get_field_str()
                # What to do if there isn't another record in this event
                if not aup.next_record(): break

            logging.info('Entering action loop...')
            if not cfg[cfgkeys[key]][uid] or targetuid is cfg[cfgkeys[key]][uid]:
                if cfg[cfgkeys[key]][chroot]:
                    chroot = cfg[cfgkeys[key]][chroot]
                else:
                    logger.warning('WARNING: There was no chroot set for some reason')
                    chroot = '/'

                logging.debug('Cleaning and sanitizing path')
                targetfilefullpath = cleanuppaths(chroot,targetfilepath,targetfilename)

                if targetaction == 'mv':
                    logging.info('Moving ' + targetfilefullpath + ' to ' + cfg[cfgkeys[key]][destination])
                    exitstatus = os.system("mv " + targetfilefullpath + " " + cfg[cfgkeys[key]][destination])
                    if exitstatus == 0:
                        logging.info('File moved successfully.')
                    else:
                        logging.error('ERROR: System returned exit code ' + exitstatus)

                elif targetaction == 'cp':
                    logging.info('copying ' + targetfilefullpath + ' to ' + cfg[cfgkeys[key]][destination])
                    exitstatus = os.system("cp -a" + targetfilefullpath + " " + cfg[cfgkeys[key]][destination])
                    if exitstatus == 0:
                        logging.info('File copied successfully.')
                    else:
                        logging.error('ERROR: System returned exit code ' + exitstatus)

                elif targetaction == 'rm':
                    logging.info('Deleting ' + targetfilefullpath)
                    exitstatus = os.system("rm -f" + targetfilefullpath)
                    if exitstatus == 0:
                        logging.info('File deleted successfully.')
                    else:
                        logging.error('ERROR: System returned exit code ' + exitstatus)
                else:
                    logging.error('ERROR: There was no defined action')
            else:
                logging.info('INFO: Possible event match, but no matching UID was set for ' + cfg[cfgkeys[key]] + '.')

    while not aup.parse_next_event():
        #logging.debug('sleeping until next event')
        time.sleep(10)

aup = None
sys.exit(0)
