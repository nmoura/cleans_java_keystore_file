#!/bin/bash
#
# cleans_java_keystore_file.sh
#
# Nilton Moura <https://nmoura.github.io>
#
# ----------------------------------------------------------------------------
#
# Cleans Java keystore file
#
# This script generates a copy of a keystore file, removing authorities which
# does not belong to the chain of a specific authority. All you have to do is
# to properly configure cleans_java_keystore_file.conf file. It also generates
# the same keystore in a PEM format file. To generate it, just pass -p or
# --pem parameter on the command line.
#
# All configuration variables in cleans_java_keystore_file.conf are mandatory,
# but keystore_issuer has a fundamental role. It’s the CN issuer that you want
# to trust. So, the script will preserve in the keystore only hierarchically
# CA’s above and below of this issuer, no mattering the depth.
#
# To read more about this script, see examples and etc., access this page:
# https://nmoura.github.io/2017/09/08/cleaning-a-java-keystore-or-preparing-\
# for-authenticate-brazilian-persons.html
#
# ----------------------------------------------------------------------------
#
usage_message="\
Usage: $(basename "$0") [-h|--help]

  -p, --pem          Creates also a keystore in PEM format
  -h, --help         Shows this message and exits
"

while test -n "$1" ; do
  case "$1" in
    -h)
      echo "$usage_message"
      exit 0
      ;;

    --help)
      echo "$usage_message"
      exit 0
      ;;

    -p)
      pem=true
      ;;

    --pem)
      pem=true
      ;;

    *)
     #invalid option
     echo "ERROR: invalid option"
     echo "$usage_message"
     exit 1
     ;;
  esac
  shift
done

#
# Loads the useful_functions file
#
useful_functions_file=$(dirname $0)/useful_functions
if [ ! -f $useful_function_file ] ; then
  echo "ERROR: useful_functions file not found."
  exit 2
else
  source $useful_functions_file
fi

#
# Defines basename and username (functions from useful_functions file)
#
define_basename
define_username

#
# Loads the configuration file
#
conf_file="$(dirname $0)/$(basename $0 | cut -d '.' -f1).conf"

if [ ! -f $conf_file ] ; then
  echo "ERROR: configuration file not found."
  exit 2
else
  source $conf_file
fi

#
# Checks if the configuration file is correctly configured
#
if [ -z "$keystore_file" ] ; then
  logger 2 "keystore_file variable must be defined in $conf_file"
  exit 2
fi
if [ ! -f "$keystore_file" ] ; then
  logger 2 "$keystore_file does not exist or cannot be read"
  exit 2
fi
if [ -z "$keystore_pass" ] ; then
  logger 2 "keystore_pass variable must be defined in $conf_file"
  exit 2
fi
if [ -z "$keystore_newfile" ] ; then
  logger 2 "keystore_newfile variable must be defined in $conf_file"
  exit 2
fi
if [ -z "$keystore_newpass" ] ; then
  logger 2 "keystore_newpass variable must be defined in $conf_file"
  exit 2
fi
if [ -z "$keystore_issuer" ] ; then
  logger 2 "keystore_issuer variable must be defined in $conf_file"
  exit 2
fi

#
# Checks if keystore_file exists
#
if [ ! -f $keystore_file ] ; then
  logger 2 "keystore file not found"
  echo "$usage_message"
  exit 2
fi

#
# Checks if keytool command is available and defines English as default
# language for keytool output
#
which keytool &> /dev/null
if [ $? != '0' ] ; then
  logger 2 "keytool command not found"
  exit 2
else
  keytool="$(which keytool) -J-Duser.language=en"
fi

#
# Creates a temporary directory
#
tmp_dir=/tmp/$basename-$(date '+%Y%m%d-%H%M%S')
mkdir $tmp_dir &> /dev/null
if [ $? != '0' ] ; then
  logger 2 "could not create temporary directory"
  exit 2
fi

#
# Exits if the user who called this script is a superuser
#
if [ "$UID" == '0' ] ; then
  logger 2 "you are a super user."
  exit 2
fi

#
# Copies the keystore to $tmp_dir
#
cp $keystore_file $tmp_dir/$keystore_newfile
if [ "$?" != "0" ] ; then
  logger 2 "file $keystore_file could not be copied to \
$tmp_dir/$keystore_newfile"
  exit 2
fi

#
# Changes the current directory to temporary directory
#
old_dir=$(pwd)
cd $tmp_dir
if [ "$?" != "0" ] ; then
  logger 2 "could not access temporary directory $tmp_dir"
  exit 2
fi

logger 0 "all prerequisites were satisfied - continuing to the cleaning \
proccess of the keystore file"

#
# Ends here the prerequisites checking
#

#
# Defines an exit status
#
exit_status=0

#
# Stores in $tmpvar_all_aliases all CA's aliases founded on $keystore_newfile
#
tmpvar_all_aliases=($($keytool -list -keystore $keystore_newfile -storepass \
  $keystore_pass | grep 'trustedCertEntry' | cut -d ',' -f 1 | sort ))
if [ "$?" != "0" ] ; then
  logger 2 "could not create an array of all aliases from keystore \
$tmp_dir/$keystore_newfile"
  exit 2
fi

#
# Stores in $tmpvar_keystore_verbose_list_file the detailed list of all found
# CA's in $keystore_newfile
#
tmpvar_keystore_verbose_list_file=$tmp_dir/tmpvar_keystore_verbose_list_file.txt
$keytool -v -list -keystore $keystore_newfile -storepass $keystore_pass \
  > $tmpvar_keystore_verbose_list_file
if [ "$?" != "0" ] ; then
  logger 2 "could not store in $tmp_dir/$tmpvar_keystore_verbose_list_file \
file a detailed list of all found CAs"
  exit 2
fi

#
# Stores a list of CA's to preserve in $tmpvar_cas_to_preserve_file file,
# according to the $keystore_issuer
#
tmpvar_cas_to_preserve_file=$tmp_dir/tmpvar_cas_to_preserve_file.txt
grep -B 5 ^"Issuer: CN=$keystore_issuer" $tmpvar_keystore_verbose_list_file \
  | egrep \(^Alias\|^Owner\|^Issuer\) > $tmpvar_cas_to_preserve_file
if [ "$?" != "0" ] ; then
  logger 2 "could not store in $tmp_dir/$tmpvar_cas_to_preserve_file file a \
list of CAs to preserve"
  exit 2
fi

#
# Creates a list of immediately high CA's aliases
#
tpmvar_issues_to_preserve=$(grep ^'Issuer' $tmpvar_cas_to_preserve_file | \
 sort | uniq | cut -d ' ' -f 2-)
if [ "$?" != "0" ] ; then
  logger 2 "could not create a list of immediately high CAs aliases to \
preserve"
  exit 2
fi

#
# Adds high CA's aliases to $tmpvar_cas_to_preserve_file, to complete the chain
#
tmpvar_remaining_issues_to_preserve="anything"
while [ "$tpmvar_issues_to_preserve" != \
 "$tmpvar_remaining_issues_to_preserve" ] ; do

  while read -r line ; do
    grep -B 5 -A 1 ^"Owner: $line" $tmpvar_keystore_verbose_list_file \
     | egrep \(^Alias\|^Owner\|^Issuer\) >> $tmpvar_cas_to_preserve_file
  done <<< "$tpmvar_issues_to_preserve"

  tmpvar_remaining_issues_to_preserve=$tpmvar_issues_to_preserve
  tpmvar_issues_to_preserve=$(grep ^'Issuer' $tmpvar_cas_to_preserve_file \
   | sort | uniq | cut -d ' ' -f 2-)

done

#
# Eliminates duplicated CA's aliases
#
tmpvar_aliases_cas_to_preserve=$(grep ^'Alias name: ' \
 $tmpvar_cas_to_preserve_file | cut -d ' ' -f3- | sort | uniq)
if [ "$?" != "0" ] ; then
  logger 2 "could not eliminate duplicated aliases"
  exit 2
fi

#
# Removes all CA's entries from $keystore_newfile which are not part of \
# $keystore_issuer in the chain
#
for aliaz in ${tmpvar_all_aliases[@]} ; do
  echo $aliaz | grep "$tmpvar_aliases_cas_to_preserve" &> /dev/null
  if [ "$?" != '0' ] ; then
    $keytool -delete -alias $aliaz -keystore $keystore_newfile -storepass \
     $keystore_pass
    if [ "$?" != "0" ] ; then
      logger 2 "could not remove $aliaz certificate from keystore \
$tmp_dir/$keystore_newfile file"
      exit 2
    fi
  fi
done

#
# Changes the keystore password of the PrivateKeyEntry of the keystore
# to the password defined in $keystore_newpass
#
tmpvar_privatekey_alias=$($keytool -list -keystore $keystore_newfile \
 -storepass $keystore_pass | grep PrivateKeyEntry | cut -d ' ' -f 1 | \
 tr -d ',')
if [ "$?" != "0" ] ; then
  logger 1 "could not get PrivateKeyEntry alias from keystore \
$tmp_dir/$keystore_newfile file"
  exit_status=1
fi

$keytool -keypasswd -alias $tmpvar_privatekey_alias -keypass \
 $keystore_pass -new $keystore_newpass -storepass $keystore_pass \
 -keystore $keystore_newfile
if [ "$?" != "0" ] ; then
  logger 1 "problem to change the keystore password of \
$tmp_dir/$keystore_newfile file"
  exit_status=1
fi

#
# Changes the store password of the keystore to the password defined in
# $keystore_newpass
#
$keytool -storepasswd -new $keystore_newpass -keystore $keystore_newfile \
 -storepass $keystore_pass
if [ "$?" != "0" ] ; then
  logger 1 "problem to change the store password of \
$tmp_dir/$keystore_newfile file"
  exit_status=1
fi

#
# Copies the new keystore to the $old_dir
#
cp $keystore_newfile $old_dir/
if [ "$?" != "0" ] ; then
  logger 2 "file $tmp_dir/$keystore_newfile could not be copied to \
$old_dir/$keystore_newfile"
  exit_status=1
else
  logger 0 "$keystore_newfile keystore file successfully created"
fi

#
# Creates a PEM keystore file, if $pem is true
#
if [ $pem ] ; then
  $keytool -importkeystore -srckeystore $keystore_newfile -destkeystore \
   $keystore_newfile.p12 -srcstoretype jks -deststoretype pkcs12 \
    -srcstorepass $keystore_newpass -deststorepass $keystore_newpass \
    &> /dev/null
  if [ "$?" != "0" ] ; then
    logger 1 "problem to create PKCS12 keystore file"
    exit_status=1
  fi

  openssl pkcs12 -in $keystore_newfile.p12 -out $keystore_newfile.pem \
   -password pass:$keystore_newpass -passout pass:$keystore_newpass \
   &> /dev/null
   if [ "$?" != "0" ] ; then
     logger 1 "problem to create PEM keystore file"
    exit_status=1
   fi

  cp $keystore_newfile.pem $old_dir/
  if [ "$?" != "0" ] ; then
    logger 1 "file $keystore_newfile.pem could not be copied to \
$old_dir/$keystore_newfile.pem"
  else
    logger 0 "$keystore_newfile.pem keystore file successfully created"
  fi
else
  logger 0 "if you wish, next time just pass the -p or --pem parameter \
to also generate a PEM format keystore file."
fi

#
# Cleans $tmp_dir directory
#
if [ "$exit_status" != "0" ] ; then
  logger 0 "the proccess was not totally successful - check above messages"
  logger 0 "leaving $tmp_dir intact for debbuging purposes"
  exit $exit_status
else
  rm -f $tmp_dir/*
  rmdir $tmp_dir
fi
