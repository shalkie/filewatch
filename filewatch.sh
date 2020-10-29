#!/usr/bin/env bash

for i in $@ ; do
  if [ "${i}" == trace ]; then
    set -o xtrace
  elif [ "${i}" == debug ]; then
    DEBUGGING=true
  fi
done

logit() {
   echo $@ >> /var/log/filewatch.log
}

logit "Starting filewatch"

logit "Defining filewatch default values..."

# Lets set the constants

config_chroot="/srv/sftp/xfer/EDM/clouderp"
config_destination="${config_chroot}/bankstatements/archive"
config_action="mv"
config_uid=429
config_key="clouderp"

EVENTID=""

processid () { 
	echo $1 | sed 's/audit(\([[:digit:]]*\)\.\([[:digit:]]*\):\([[:digit:]]*\)):/\1.\2/'
	}

geteventid () {
	for i in $@; do
           key=$(echo $i | sed 's/\(.*\)=\(.*\)/\1/') 
           value=$(echo $i | sed 's/\(.*\)=\(.*\)/\2/') 
	   if [ "$key" == "msg" ] ; then 
	   echo $(processid "$value")
	   fi
	done
}

getkv() {
	for i in $@ ; do
	  if [ "$1" != ${i} ] ; then
           key=$(echo $i | sed 's/\(.*\)=\(.*\)/\1/') 
           value=$(echo $i | sed 's/\(.*\)=\(.*\)/\2/; s/"//g') 
	   if [ "$key" == "$1" ] ; then
		echo $value
	   fi
	  fi
        done
} 

processtherecord () {
  logit "Processing the current record"
  logit "Record type is $recordtype"
	case $recordtype in
		CWD)
			event_cwd="$(getkv cwd "${REPLY}")";
      [ -n "${DEBUGGING}" ] && logit event_cwd $event_cwd
		;;
		SYSCALL)
			event_uid="$(getkv uid "${REPLY}")";
			event_auid="$(getkv auid "${REPLY}")";
			event_fsuid="$(getkv fsuid "${REPLY}")";
			event_key="$(getkv key "${REPLY}")";
			[ -n "${DEBUGGING}" ] && logit event_uid $event_uid
			[ -n "${DEBUGGING}" ] && logit event_auid $event_auid
			[ -n "${DEBUGGING}" ] && logit event_fsuid $event_fsuid
			[ -n "${DEBUGGING}" ] && logit event_key $event_key
		;;
		PATH)
			event_name="$(getkv name "${REPLY}")";
			[ -n "${DEBUGGING}" ] && logit event_name $event_name
		;;
		*)
		;;
	esac 

	[ -n "${DEBUGGING}" ] && printcurrentkeys 

	}

printcurrentkeys () {
    logit Current keys are:
    logit event_key = $event_key
    logit event_id = $event_id
    logit event_cwd = $event_cwd
    logit event_uid = $event_uid
    logit event_auid = $event_auid
    logit event_name = $event_name
    logit event_fsuid = $event_fsuid
    logit config_chroot = $config_chroot
    logit config_destination = $config_destination
    logit config_action = $config_action
    logit config_uid = $config_uid
    logit config_key = $config_key
}

dotheneedfulls() {
     [ -n "${DEBUGGING}" ] && logit "Doing the needfulls"
     [ -n "${DEBUGGING}" ] && logit "event_key is $event_key"
     [ -n "${DEBUGGING}" ] && logit "config_key is $config_key"
     [ -n "${DEBUGGING}" ] && logit "event_uid is $event_uid"
     [ -n "${DEBUGGING}" ] && logit "config_uid is $config_uid"
	   if [ "${event_key}" != "${config_key}" ] ; then
	    logit "No key Match; Skipping this event" 
	   elif [ "${event_uid}" != "${config_uid}" ]; then
	    logit "No matching UID"
	  else
	    if [ -f "${config_path}/$event_name" ] ; then
	      logit moving file... $config_action -v ${config_path}/${event_name} $config_destination
	      $config_action -v ${config_path}/${event_name} $config_destination
      else
        logit "File doesn't exist"
	    fi
    fi
}

echo entering main loop
while true; 
do
  sleep 1 
  read -r 
  [ -n "${DEBUGGING}" ] && logit $REPLY 
  if [ -n "${REPLY}" ]; 
  then 
    [ -n "${DEBUGGING}" ] && logit "Getting eventid from ${REPLY}"
    CURRENTEVENTID=$(geteventid "${REPLY}")
    unset recordtype
    [ -n "${DEBUGGING}" ] && logit "Getting Record Type"
    recordtype=$(getkv type "${REPLY}")
    logit Processing type $recordtype

    if [ -z "$EVENTID" ] ; 
    then
      [ -n "${DEBUGGING}" ] && logit "Seeing first event"
      EVENTID="${CURRENTEVENTID}"
    elif [ '$recordtype' == 'EOE' ] ; then
      logit "Reached the end of records"
      dotheneedfulls
    elif [ "$EVENTID" != "${CURRENTEVENTID}" ] ; then
      logit "Seeing new event, Processing $EVENTID"
      dotheneedfulls
      logit "Goodbye to $EVENTID"
      logit "-------------------"
      logit "Hello to $CURRENTEVENTID"
      EVENTID="${CURRENTEVENTID}"
      unset event_cwd event_uid event_auid event_fsuid event_key event_name event_id
      event_id="$EVENTID"
      export EVENT
      processtherecord
    else
      logit "Processing next record in event $event_id"
      processtherecord
    fi


  fi
done
