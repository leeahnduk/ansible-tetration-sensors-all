#!/bin/bash

# This script requires privilege users to execute.
#
# If pre-check is not skipped, checks prerequisites for installing and running
# tet-sensor on Linux hosts.
#
# If all prerequisites are met and installation succeeds, the script exits
# with 0. Otherwise it terminates with a non-zero exit code for the first error
# faced during execution.
#
# The failure message is written to a logfile if passed, stdout otherwise.
# Pre-check can skip IPv6 test by passing the --skip-ipv6 flag.
#
# Exit code - Reason:
# 255 - root was not used to execute the script
# 240 - invalid parameters are detected
# 239 - installation failed
# 238 - saving zip file failed
# 237 - sensor upgrade failed
#   1 - pre-check: IPv6 is not configured or disabled
#   2 - pre-check: su is not operational
#   3 - pre-check: curl is missing or not from rpmdb
#   4 - pre-check: curl/libcurl compatibility test failed
#   5 - pre-check: /tmp is not writable
#   6 - pre-check: /usr/local/tet cannot be created
#   7 - pre-check: ip6tables missing or needed kernel modules not loadable
#   8 - pre-check: package missing

# Do not trust system's PATH
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SCRIPT_VERSION=1.0
LOG_FILE=
CL_HTTPS_PROXY=
PROXY_ARGS=
SKIP_IPV6=0
DO_PRECHECK=1
NO_INSTALL=0
DISTRO=
VERSION=
SENSOR_VERSION=
SENSOR_ZIP_FILE=
SAVE_ZIP_FILE=
CLEANUP=
LIST_VERSION="False"
FORCE_UPGRADE=
UUID_FILE=
# Sensor type is chosen by users on UI
SENSOR_TYPE="enforcer"
# Packages used by sensor without version requirement, except rpm
SENSOR_PACKAGE_USAGE=("unzip" "cpio" "sed" "lsof")

function print_usage {
  echo "Usage: $0 [--skip-pre-check] [--no-install] [--logfile=<filename>] [--proxy=<proxy_string>] [--skip-ipv6-check] [--help] [--version] [--sensor-version=<version_info>] [--ls] [--file=<filename>] [--save=<filename>] [--new] [--force-upgrade] [--upgrade=<filename>]"
  echo "  --skip-pre-check: skip pre-installation check (on by default)"
  echo "  --no-install: will not download and install sensor package onto the system"
  echo "  --logfile=<filename>: write the log to the file specified by <filename>"
  echo "  --proxy=<proxy_string>: set the value of CL_HTTPS_PROXY, the string should be formatted as http://<proxy>:<port>"
  echo "  --skip-ipv6-check: skip IPv6 test"
  echo "  --help: print this usage"
  echo "  --version: print current script's version"
  echo "  --sensor-version=<version_info>: select sensor's version; e.g.: '--sensor-version=3.1.1.53.devel'; will download the latest version by default"
  echo "  --ls: list all available sensor versions for your system (will not list pre-3.1 packages); will not download any package"
  echo "  --file=<filename>: provide local zip file to install sensor instead of downloading it from cluster"
  echo "  --save=<filename>: download and save zip file as <filename>"
  echo "  --new: cleanup installation to enable fresh install"
  echo "  --force-upgrade: force sensor upgrade to version given by --sensor-version flag; e.g.: '--sensor-version=3.3.1.53.devel --force-upgrade'; apply the latest version by default if --sensor-version flag is missing"
  echo "  --upgrade=<filename>: trigger sensor whose uuid is listed in <filename> upgrade to version given by --sensor-version flag; e.g.: '--sensor-version=3.3.1.53.devel --upgrade=/usr/local/tet/sensor_id'; apply the latest version by default if --sensor-version flag is missing"
}

function print_version {
  echo "Installation script for Cisco Tetration Agent (Version: $SCRIPT_VERSION)."
  echo "Copyright (c) 2018-2019 Cisco Systems, Inc. All Rights Reserved."
}

function log {
  if [ -z $LOG_FILE ]; then
    echo $@
  else
    echo $@ >> $LOG_FILE
  fi
}

function fullname {
  case "$1" in
    /*) echo $1
    ;;
    ~*) echo "$HOME$(echo $1 | awk '{print substr ($0,2)}')"
    ;;
    *) echo $(pwd)/$1
    ;;
  esac
}

function centos_check_package {
  for i in "${SENSOR_PACKAGE_USAGE[@]}" ;
    do
      rpm -q $i > /dev/null
      if [ $? -ne 0 ] ; then
        log "Error: No $i installed"
        PACKAGE_MISSING=1
      fi
    done  
}

function ubuntu_check_package {
  for i in "${SENSOR_PACKAGE_USAGE[@]}" ;
    do
      dpkg -s $i > /dev/null
      if [ $? -ne 0 ] ; then
        rpm -q $i > /dev/null
        if [ $? -ne 0 ] ; then
          log "Error: No $i installed"
          PACKAGE_MISSING=1
        fi
      fi
    done  
}

# Compare two version number
# Return 0 if op = '='
# Return 1 if op = '>'
# Return 2 if op = '<'
function compare_version {
  if [ -z $1 ] ; then
    if [ -z $2 ] ; then
      return 0
    else
      return 2
    fi
  fi
  if [ -z $2 ] ; then
    return 1
  fi
  if [ $1 == $2 ] ; then
    return 0
  fi
  local IFS=".-"
  local i ver1=($1) ver2=($2)
  local ver1_first_arg ver1_second_arg ver2_first_arg ver2_second_arg
  for (( i=${#ver1[@]}; i<${#ver2[@]}; i++ )) ; do
    ver1[i]=0
  done
  for (( i=0; i<${#ver1[@]}; i++ )) ; do
    if [ -z ${ver2[i]} ] ; then
      ver2[i]=0
    fi
    ver1_first_arg=${ver1[i]//[A-Za-z]/}
    [ -z $ver1_first_arg ] && ver1_first_arg=0
    ver2_first_arg=${ver2[i]//[A-Za-z]/}
    [ -z $ver2_first_arg ] && ver2_first_arg=0
    if [ $ver1_first_arg -gt $ver2_first_arg ] ; then
      return 1
    elif [ $ver1_first_arg -lt $ver2_first_arg ] ; then
      return 2
    else
      ver1_second_arg=${ver1[i]//[0-9]/}
      [ -z $ver1_second_arg ] && ver1_second_arg=0
      ver2_second_arg=${ver2[i]//[0-9]/}
      [ -z $ver2_second_arg ] && ver2_second_arg=0
      if [ $ver1_second_arg \> $ver2_second_arg ] ; then
        return 1
      elif [ $ver1_second_arg \< $ver2_second_arg ] ; then
        return 2
      fi
    fi
  done
  return 0
}

# check if package version meets requirement
# args: package name, version, release
# e.g.: openssl, 1.0.2k, 16.el7
function check_pkg_version_rpm {
  package_version="$(rpm -qi $1 | awk -F': ' '/Version/ {print $2}' | awk -F' ' '{print $1}')"
  package_version=(${package_version[0]})
  if [ -z $package_version ] ; then
    log "Error: No $1 installed"
    return 1
  fi
  package_release="$(rpm -qi $1 | awk -F': ' '/Release/ {print $2}' | awk -F' ' '{print $1}')"
  package_release=(${package_release[0]})
  compare_version $package_version $2 
  compare_result=$?
  if [ $compare_result -eq 0 ] ; then
    compare_version "$package_release" $3
    if [ $? -eq 2 ] ; then
      log "Error: Lower version of $1 installed"
      log "$package_version-$package_release detected; $2-$3 required"
      return 1 
    fi
  elif [ $compare_result -eq 2 ] ; then
    log "Error: Lower version of $1 installed"
    log "$package_version-$package_release detected; $2-$3 required"
    return 1
  fi
  return 0
}

function check_pkg_version_dpkg {
  package_version_release="$(dpkg -s $1 | awk -F': ' '/Version/ {print $2}' | awk -F' ' '{print $1}')"
  package_version_release=(${package_version_release[0]})
  if [ -z $package_version_release ] ; then
    # also check rpm
    check_pkg_version_rpm $1 $2 $3
    [ $? -ne 0 ] && return 1
    return 0
  fi 
  package_version="${package_version_release%-*}"
  package_release="${package_version_release#*-}"
  compare_version "${package_version}" $2 
  compare_result=$?
  if [ $compare_result -eq 0 ] ; then
    compare_version "${package_release%ubuntu*}" $3
    if [ $? -eq 2 ] ; then
      log "Error: Lower version of $1 installed"
      log "$package_version-$package_release detected; $2-$3 required"
      return 1 
    fi
  elif [ $compare_result -eq 2 ] ; then
    log "Error: Lower version of $1 installed"
    log "$package_version-$package_release detected; $2-$3 required"
    return 1
  fi
  return 0
}

function pre_check {
  log ""
  log "### Testing tet-sensor prerequisites on host \"$(hostname -s)\" ($(date))"
  log "### Script version: $SCRIPT_VERSION"

  # Used for detecting when running on Ubuntu
  DISTRO=
  if [ -e /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$NAME
  fi
  PACKAGE_MISSING=
  # Check packages
  log "Detecting dependencies"
  awk -W version > /dev/null 2>&1
  if [ $? -ne 0 ] ; then
    log "Error: No awk installed"
    return 8
  fi
  flock -V > /dev/null 2>&1
  if [ $? -ne 0 ] ; then
    log "Error: No flock installed"
    PACKAGE_MISSING=1
  fi
  dmidecode_version=$(dmidecode -V 2>/dev/null)
  if [ $? -ne 0 ] ; then
    PACKAGE_MISSING=1
    log "Error: No dmidecode installed"
  else
    compare_version $dmidecode_version "2.11"
    if [ $? -eq 2 ] ; then
      log "Error: Lower version of dmidecode installed"
      log "$dmidecode_version detected; 2.11 required"
      PACKAGE_MISSING=1
    fi
  fi
  if [ "$DISTRO" != "Ubuntu" ] ; then
    centos_check_package
    check_pkg_version_rpm "openssl" "0.9.8e"
    [ $? -ne 0 ] && PACKAGE_MISSING=1
    if [ $SENSOR_TYPE == "enforcer" ] ; then
      check_pkg_version_rpm "ipset" "6.11" "4"
      [ $? -ne 0 ] && PACKAGE_MISSING=1
      if [ "$DISTRO" == "SLES" ] ; then
        check_pkg_version_rpm "iptables" "1.4.6" "2.11.4"
        [ $? -ne 0 ] && PACKAGE_MISSING=1
      else
        check_pkg_version_rpm "iptables" "1.4.7" "16"
        [ $? -ne 0 ] && PACKAGE_MISSING=1
      fi
    fi
  else
    ubuntu_check_package
    check_pkg_version_dpkg "openssl" "0.9.8e"
    [ $? -ne 0 ] && PACKAGE_MISSING=1
    if [ $SENSOR_TYPE == "enforcer" ] ; then
      check_pkg_version_dpkg "ipset" "6.11" "4"
      [ $? -ne 0 ] && PACKAGE_MISSING=1
      check_pkg_version_dpkg "iptables" "1.4.7" "16"
      [ $? -ne 0 ] && PACKAGE_MISSING=1
    fi
  fi
  if [ ! -z $PACKAGE_MISSING ] ; then
    return 8
  fi

  # detect whether IPv6 is enabled
  if [ $SENSOR_TYPE == "enforcer" ] && [ $SKIP_IPV6 -eq 0 ]; then
    log "Detecting IPv6"
    if [ ! -e /proc/sys/net/ipv6 ]; then log "Error: IPv6 is not configured"; return 1; fi
    v=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
    ret=$?
    if [ $ret -ne 0 ]; then log "Error: Failed to verify if IPv6 is enabled: ($ret)"; return 1; fi
    if [ $v = 1 ]; then log "Error: IPv6 is disabled"; return 1; fi
    which ip6tables > /dev/null 2>&1
    if [ $? -ne 0 ]; then log "Error: ip6tables command is missing"; return 7; fi
    ip6tables -nvL > /dev/null 2>&1
    if [ $? -ne 0 ]; then log "Error: ip6tables command is not functional (check kernel modules)"; return 7; fi
  fi

  log "Testing su"
  # detect whether su could be invoked
  (su nobody -s /bin/bash -c date >> /dev/null) &
  PID=$!
  sleep 3; kill -9 $PID 2> /dev/null
  wait $PID
  if [ $? -ne 0 ]; then
    log "Error: su failed to return within specified time"
    return 2
  fi

  log "Detecting curl/libcurl version"
  NO_CURL=0
  CURL_VER_REL=$(rpm -q --qf "%{version}-%{release}" curl)
  if [ $? -ne 0 ]; then
    which curl > /dev/null 2>&1
    if [ $? -ne 0 ]; then
      log "Error: No curl installed"
      return 3
    fi
    if [ "$DISTRO" != Ubuntu ]; then
      log "Error: curl present but not in rpmdb"
      return 3
    fi
    NO_CURL=1
  fi

  if [ $NO_CURL -eq 0 ]; then
    log "Running curl/libcurl compatibility test"
    NO_LIBCURL=0
    LIBCURL=$(rpm -q libcurl) || LIBCURL=$(rpm -q libcurl4)
    [ $? -ne 0 ] && log "Error: No libcurl installed?" && NO_LIBCURL=1

    if [ $NO_LIBCURL -ne 1 ]; then
      LIBCURL_VER=$(rpm -q libcurl-$CURL_VER_REL) || LIBCURL_VER=$(rpm -q libcurl4-$CURL_VER_REL)
      if [ $? -ne 0 ] || [ "$LIBCURL_VER" != "$LIBCURL" ]; then
        log "Error: curl and libcurl version not matching. $LIBCURL vs $LIBCURL_VER. This could be an issue."
        return 4
      fi
      log "$CURL_VER_REL"
      log "$LIBCURL_VER"
    fi
  fi

  log "Testing /tmp/"
  RAND_NUM=$RANDOM
  su nobody -s /bin/bash -c "echo $RAND_NUM > /tmp/$RAND_NUM"
  ret=$?
  if [ $ret -ne 0 ]; then
    log "Error: Cannot create file in /tmp/: ($ret)"
    return 5
  fi
  rm -rf /tmp/$RAND_NUM

  log "Testing /usr/local/tet/"
  if [ ! -e  /usr/local/tet/ ]; then
    mkdir -p /usr/local/tet
    ret=$?
    if [ $ret -ne 0 ]; then
      log "Error: Cannot create /usr/local/tet: ($ret)"
      return 6
    fi
    rm -rf /usr/local/tet
  else
    # check the expected processes are running
    t=$(ps -e | grep tet-engine)
    te1=$(echo $t | awk '{ print $4 }')
    te2=$(echo $t | awk '{ print $8 }')
    t=$(ps -e | grep tet-sensor)
    ts1=$(echo $t | awk '{ print $4 }')
    ts2=$(echo $t | awk '{ print $8 }')
    if [ "$te1" = "tet-engine" ] && [ "$te2" = "tet-engine" ] && [ "$ts1" = "tet-sensor" ] && [ "$ts2" = "tet-sensor" ] ; then
      log "/usr/local/tet already present. Expected tet-engine and tet-sensor instances found"
    else
      log "/usr/local/tet already present. Expected tet-engine and tet-sensor instances NOT found"
    fi
  fi

  log "### Pre-check Passed"
  return 0
}

function check_host_version {
   # Check for Oracle Linux
   # Older version does not have /etc/os-release
   # Also the /etc/redhat-release is showing Red Hat Linux version
   # So we need to check the file /etc/oracle-release first
   # output looks like this "Oracle Linux Server release 6.10"
   if [ -e /etc/oracle-release ] ; then
      local releasestring=$(cat /etc/redhat-release | grep -e "^Oracle")
      DISTRO=$(cat /etc/oracle-release | awk '{print $1$3}')
      VERSION=$(cat /etc/oracle-release | awk -F 'release ' '{print $2}' | awk '{print $1}')
      [ "$DISTRO" = "OracleServer" ] && return 0
   fi

   # SuSE has consistent version in the specific SuSE-release file, dropped for SLES15
   if [ -e /etc/SuSE-release ] ; then
       DISTRO=$(cat /etc/SuSE-release | head -1 | awk '{print $1$2$3$4}')
       VERSION=$(cat /etc/SuSE-release | grep 'VERSION' | awk -F '=' '{print $2}' | awk '{print $1}')
       VERSION=$VERSION.$(cat /etc/SuSE-release | grep 'PATCHLEVEL' | awk -F '=' '{print $2}' | awk '{print $1}')
       [ "$DISTRO" = "SUSELinuxEnterpriseServer" ] && return 0
   fi

   # Check for redhat/centos
   # In CentOS, string looks like this: "CentOS release 6.x (Final)"
   # CentOS Linux release 7.2.1511 (Core)
   # But in RHEL, string looks like this: "Red Hat Enterprise Linux Server release 6.x (Santiago)"
   # Or "Red Hat Enterprise Linux release 8.0 (Ootpa)"
   # But there might be lines with comments

   if [ -e /etc/redhat-release ] ; then
       local releasestring=$(cat /etc/redhat-release | grep -e "^Cent" -e "^Red")
       if [ $? -eq 0 ] ; then
	   DISTRO=$(echo $releasestring | awk '{print $1}')
	   [ $DISTRO = "Red" ] && DISTRO="RedHatEnterpriseServer"
	   VERSION=$(echo $releasestring | awk -F 'release ' '{print $2}' | awk '{print $1}' | awk -F "." '{printf "%s.%s", $1, $2}')
	   [ "$VERSION" = "5." ] && VERSION="5.0"
	   [ "$(echo $VERSION | head -c 1)" = "5" ] && [ "$SENSOR_TYPE" = "enforcer" ] && echo "Warning: Enforcer not supported on $DISTRO.$VERSION" && SENSOR_TYPE="sensor"
	   return 0
       fi
   fi

   # Ubuntu has os-release which is a script
   if [ -e /etc/os-release ] ; then
      . /etc/os-release
      DISTRO=$NAME
      VERSION=$VERSION_ID
      [ "$VERSION" = "12.04" ] && [ "$SENSOR_TYPE" = "enforcer" ] && echo "Warning: Enforcer not supported on $DISTRO.$VERSION" && SENSOR_TYPE="sensor"
      if [ "$NAME" = "SLES" ] ; then
	  DISTRO="SUSELinuxEnterpriseServer"
	  if [ "$VERSION" = "15" ] ; then
	      VERSION=15.0
	  fi
      fi
      return 0
   fi

   # Unknown OS/Version
   DISTRO="Unknown"
   VERSION=`uname -a`
   return 1
}

# Check if old binaries already exist or sensor registered in rpm db
function check_sensor_exists {
  if [ -e /usr/local/tet/tet-sensor ] || [ -e /usr/local/tet/tet-enforcer ] ; then
    log "Sensor binaries exist"
    return 1
  fi
  if [ ! -z "$(rpm -qa tet-sensor)" ] || [ ! -z "$(rpm -qa tet-sensor-site)" ] ; then
    log "Sensor found in rpm db"
    return 1
  fi
  log "Sensor not found"
  return 0
}

function perform_install {
  log ""
  log "### Installing tet-sensor on host \"$(hostname -s)\" ($(date))"

  if [ ! -z $CLEANUP ] ; then
    log "cleanning up before installation"
    if [ ! -z "$(rpm -qa tet-sensor)" ] ; then 
      rpm -e tet-sensor
    fi
    if [ ! -z "$(rpm -qa tet-sensor-site)" ] ; then
      rpm -e tet-sensor-site
    fi
    rm -rf /usr/local/tet
  fi
  [ $NO_INSTALL -eq 2 ] && !(check_sensor_exists) && return 1

  # Create a random folder in /tmp, assuming it's writable (pre-check done)
  TMP_DIR=$(mktemp -d /tmp/tet.XXXXXX)
  log "Created temporary directory $TMP_DIR"
  EXEC_DIR=$(pwd)
  log "Execution directory $EXEC_DIR"
  cd $TMP_DIR

cat << EOF > tet.user.cfg
ACTIVATION_KEY=2452436f76b8c614382df12b96aa36184be87610
HTTPS_PROXY=$CL_HTTPS_PROXY
EOF

cat << EOF > ta_sensor_ca.pem
-----BEGIN CERTIFICATE-----
MIIF4TCCA8mgAwIBAgIJAIQXeQ8u/YZFMA0GCSqGSIb3DQEBCwUAMH8xCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTERMA8GA1UEBwwIU2FuIEpvc2UxHDAaBgNVBAoM
E0Npc2NvIFN5c3RlbXMsIEluYy4xHDAaBgNVBAsME1RldHJhdGlvbiBBbmFseXRp
Y3MxFDASBgNVBAMMC0N1c3RvbWVyIENBMB4XDTIwMDEwNzAxMjg1OVoXDTMwMDEw
NDAxMjg1OVowfzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMREwDwYDVQQHDAhT
YW4gSm9zZTEcMBoGA1UECgwTQ2lzY28gU3lzdGVtcywgSW5jLjEcMBoGA1UECwwT
VGV0cmF0aW9uIEFuYWx5dGljczEUMBIGA1UEAwwLQ3VzdG9tZXIgQ0EwggIiMA0G
CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDIjdqCzpjb072tcf6gNBi/coHfSiRq
2bQPk6Gc8dEDuye3RJRZZBTL/uIhWwPPeSKJZzeFG0N80bMcxWjWdjQjj/cb5uzv
G2+VNs15HYtx2jAlsauZqkKA7SVnpUxly+kxpCgCOgayWuIk8hxfL+5qx6LYSSeM
ukrAaHIjBwdOR7o7i/VJShTPNwCeWMMcIoCATXd/y9qTvUULwQ4VNz3P8V05yHAN
YommGnUTZqEHEn4V20tQy9Jc77yDb5gAGwWmhzkzYTlWjvw5XTPpWfFt8MiyosV2
0lpXQYUhvYMViLyTOV81izEqAFSfhM+akMGHiHyDFCzYBNWypCNnoMLkY43hMjA5
g1L2a5kyEgKPO9JHQqNmY0eM3CH6eTSeXpEIwqadDgxuyB9gBJsTsy2/gxgUskLj
oYntXxyU74yjE/kyGXzdLNJv/LKg5zBz+Z9QQJRliNym47SpigIb5ErKqon0lOP3
boaJeApHEolLLNvZXp4dRMRkuxC6Iws3vJNFvTkPD9IzFygiYDH+rSPulKPEsT0u
/50XtBnvZ04ichdSfmliw0JbRfs8kVkOKeTo8iGDnTwZwLDHZCpdiEY1W6Mi8Ox7
gfucyq0+IyAOUzJHmdKgqAhG6AuvyJYNB2wAKSxRPZ3Z7CQw75WQoZYXLsn8KEov
SecojDEByLtgwwIDAQABo2AwXjAdBgNVHQ4EFgQUC0imxW3YR9HXiUc90WTsNzwY
ETswHwYDVR0jBBgwFoAUC0imxW3YR9HXiUc90WTsNzwYETswDwYDVR0TAQH/BAUw
AwEB/zALBgNVHQ8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAJC4F1YCgfsPZelR
WFuKM7m9QwhSS0tuDWWhqc5hLFm2AZ7B5Cz1jH8JFfAUsmF6K69CTpR5pQGUkGiR
JFX5BVuhxUFJ56RWWOTUzrvtfcJk3w5ugfuvc/AGf/k/BgJZHXzSu0/UyyNaJ4oA
RHVMtzYc0/SZIclq6+7xM3dR+UMN+emf6v5NMYSiB6DKnKie9Ou6LkA3tfdR44Yk
fk0i6yJvFili9+8Bhh9Hw5c0jmJYP9zy1biKEWqDOdU5spK5xVeh3H8XoeCUXSyR
YtPDx/piSfVlAvoS1RArSKk9oYhCZnYWLwWZHDNiuAHhuh0d1uKnAwd9m/L05544
L+hJizHghBTrQvAvA1WgtADBO3hIqxCTrMFvWJCiQKo/9ynPRfFnJE/tKZ+relTK
tajThnJH48lz5D+FJPeU0UtLL7H3lVWYgZOmMwL04HmmAwbHe8dAGjFchcA3zXw1
+KYkQZIIdh8nu9oqZaONLpW5HlTDF66sNT/ufU+G9SeK7ZQClSRF+be91G5H8hBb
vmM4DSAQEOV0jQlweGz1NeUlpMpxPlcVo7gUp89xwJFRAvPLZ9FBbjsuGYaJ7OV6
pVDcDstVtokrAWgkjHYhVx9SFIczjnP3L1B6ycLm537IBEQ+gU3lDpRRTwGIHBhc
/81yAPXPywPe8D+aNpjkgK1D28S7
-----END CERTIFICATE-----

EOF

  # Decide which key to used for validation of whether the package is properly signed.
  # If the key already exist we won't overwrite it.
  if [ ! -e sensor-gpg.key ] ; then
      DEV_SENSOR=false
      if [ "$DEV_SENSOR" = true ] ; then

          # This is the dev public sensor signing key.
cat << EOF > sensor-gpg.key
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.11 (GNU/Linux)

mQENBFbECa0BCADQV84MekXnIZB7lKBBn+Hfq6MTgl/0SIZCSQaiznXZ1oKwcIIq
izU4kE/rY8XoOZdIataFcMYycH4U5NkAx11DdvSH6hrIG9BmIlcZKw92oE/YLgZP
xCUug2UDAI8QLZawPBttwal/LU9oeuKHeF8K4iIlmq3Z38KLhGPsD6Tvhl2/bAez
xyp2cFRrKcvYdaKIA6aBHHLSpfo+wXUXHtI+vyBd6Hp+5BrqbwZvFT7bnD7csOAx
hWs9MX2wm4ANmlTWed00pEMjS5iOTwzPeAlQlyleLXEjtXzoCEuq+9ufEirvDVqb
JQeL/pxGYN80w625h4EOJ92/L7XTVUwlPJnxABEBAAG0MlNlbnNvciBEZXYgS2V5
IDxzZW5zb3ItZGV2QHRldHJhdGlvbmFuYWx5dGljcy5jb20+iQE+BBMBAgAoBQJW
xAmtAhsDBQkJZgGABgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRAlscFprx/C
b3YHB/90K7lK5wwo+H+EccA9JQ19xnFK78M8UGgGj6QT2rcf1NJgTD2FXlpIEVGZ
yf3UBhyTdhlM0RsyIE4S65XrorgulM4Hzy94/y0kSRBJfnnFBKI1uNJVRupY4Y/9
WJrV7y1JN0ubFpjBdHKrKqq9822XSLVF7F3ZzLmwRMMLtFDi+leHnFCZ0OY4z7Yv
wd1XGZNhaApryQUZbjSIOgiTQCvTN+P0EEo73sm0rUxnpvQapzbWUnAWAoCI4vbb
q57mUGQZ7tYEeooEiTjk9xyU8PA0cRVarMbMNoXZtvu+xW0ipYRx6zh7Od5enGFP
LxrgudPMvK79Z22e+SZ7GiwFO5ON
=jaK+
-----END PGP PUBLIC KEY BLOCK-----
EOF

      else

          # This is the prod public sensor signing key.
cat << EOF > sensor-gpg.key
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2.0.14 (GNU/Linux)

mQENBFYVKHUBCACv6ZaWxa0/VptX9YJvnLEZvPSCV7idmbi0K911bYCY7OTpCzl1
tfDJO1SLiLeyT88Rq8PYzjY3fZqtdn3l9HTGkKqLbHOFV3qWgCau2I3SXEiIIis+
TL50zTXnF05kUKdYWXIjWgM8oD8GHQA+oWgyKWFZgA32rmcwIshndrP406U1b31N
sdo0AMbfa2nY5CHj31Cyg2/t53NOOCcVasCZ1Jx5MEkNmyNAUDtG1HbeTCjhG+Qn
ul4ugICRKiPtGsGlAhV+cI8sX9GUgepp0AzCaCEVmudwIuAT5+s0NGXqKaLTqBPV
t1fWk4U9Nw1BKd/AtFTy9u1uju0TVsOwO6XrABEBAAG0NlRldHJhdGlvbiBTZW5z
b3IgPHNlbnNvci1hZG1pbkB0ZXRyYXRpb25hbmFseXRpY3MuY29tPokBPgQTAQIA
KAUCVhUodQIbAwUJEswDAAYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQkuMZ
7s+YSL4Q1AgAmav2IsXsUgXu5rzBeTXD+0kuwX36MJg8g4/4nwxla2bQMmhzCuC8
436FX5h3eR3Mipviah3xmw8yolfYmBNmINFfl4mAbXa8WAPatdD0fL1AXdRGre1c
EI9kUIR0WfUIVURkZJPNsdn6Jass3ZUhw51v9o0gEi5GPFtHCXtvZR2BIwZ89mUK
0qS1pL5w0zezZAyB7A6tJFy+bI1rYX833oNsTMIUT+hMcpCVIWTWbUytxHb8SGmN
84Bk9j+nyofYOyrSgNLCbZe01YFNbjH9u0f/DvGjRE8km32z073AwSEHoq7CTnJQ
fEqigBGTJ6FXVHUQM4BFVmdknmL9LMd7lg==
=BN2J
-----END PGP PUBLIC KEY BLOCK-----
EOF

      fi

  fi

  # Donot check_host_version if we trigger sensor upgrade in backend
  if [ -z $UUID_FILE ] ; then
    # Download the package with config files
    PKG_TYPE="sensor_w_cfg"
    check_host_version
    [ $? -ne 0 ] && log "Error: Unsupported platform $DISTRO-$VERSION" && rm -rf $TMP_DIR && return 1
  fi

  CHK_SUM=""
  CONTENT_TYPE=""
  TS=$(date -u "+%Y-%m-%dT%H:%M:%S+0000")
  HOST="https://192.168.30.5"
  API_KEY=fb41190aa9ee4f79b1de1ebfcd838d8a
  API_SECRET=84dbf0d8bc02113deb1b595c11a9c7d13f12d044
  ARCH=$(uname -m)
  if [ $LIST_VERSION = "True" ] ; then
    METHOD="GET"
    URI="/openapi/v1/sw_assets/download?pkg_type=$PKG_TYPE\&platform=$DISTRO-$VERSION\&arch=$ARCH\&list_version=$LIST_VERSION"
    URI_NO_ESC="/openapi/v1/sw_assets/download?pkg_type=$PKG_TYPE&platform=$DISTRO-$VERSION&arch=$ARCH&list_version=$LIST_VERSION"
  elif [ ! -z $UUID_FILE ] ; then
    uuid=$(head -n 1 "$UUID_FILE")
    METHOD="POST"
    URI="/sensor_config/upgrade/$uuid?sensor_version=$SENSOR_VERSION"
    URI_NO_ESC="/sensor_config/upgrade/$uuid?sensor_version=$SENSOR_VERSION"
  else # regular download
    METHOD="GET"
    URI="/openapi/v1/sw_assets/download?pkg_type=$PKG_TYPE\&platform=$DISTRO-$VERSION\&arch=$ARCH\&sensor_version=$SENSOR_VERSION"
    URI_NO_ESC="/openapi/v1/sw_assets/download?pkg_type=$PKG_TYPE&platform=$DISTRO-$VERSION&arch=$ARCH&sensor_version=$SENSOR_VERSION"
  fi
  TMP_FILE=tmp_file
  RPM_FILE=tet-sensor-$DISTRO-$VERSION.rpm
  rm -rf $TMP_FILE
  # Calculate the signature based on the params
  # <httpMethod>\n<requestURI>\n<chksumOfBody>\n<ContentType>\n<TimestampHeader>
  MSG=$(echo -n -e "$METHOD\n$URI_NO_ESC\n$CHK_SUM\n$CONTENT_TYPE\n$TS\n")
  SIG=$(echo "$MSG"| openssl dgst -sha256 -hmac $API_SECRET -binary | openssl enc -base64)
  REQ=$(echo -n "curl $PROXY_ARGS -v -X $METHOD --cacert ta_sensor_ca.pem $HOST$URI -w '%{http_code}' -o $TMP_FILE -H 'Timestamp: $TS' -H 'Content-Type: $CONTENT_TYPE' -H 'Id: $API_KEY' -H 'Authorization: $SIG'")
  if [ -z $SENSOR_ZIP_FILE ] ; then
    count=0
    until [ $count -ge 3 ]
    do
      status_code=$(sh -c "$REQ")
      curl_status=$?
      if [ $curl_status -ne 0 ] ; then
        log "Curl error: $curl_status"
        return 1
      fi
      if [ $status_code -eq 200 ] ; then
        break
      fi
      log "Failed in request $REQ"
      echo "Status code: $status_code"
      if [ -e $TMP_FILE ] ; then
        resp_info=$(cat $TMP_FILE)
        log "Error details: ${resp_info:0:512}" # log download failure and truncate it
      fi
      count=$[$count+1]
      echo "Retry in 15 seconds..."
      sleep 15
    done
    [ $status_code -ne 200 ] && cd $EXEC_DIR && rm -rf $TMP_DIR && return 1
  fi
  [ ! -z $UUID_FILE ] && cd $EXEC_DIR && rm -rf $TMP_DIR && return 0 
  if [ $LIST_VERSION = "True" ] ; then
    if [ -e $TMP_FILE ] ; then
      local IFS=
      details=$(cat $TMP_FILE)
    fi
    echo "Available version:" && echo $details && cd $EXEC_DIR && rm -rf $TMP_DIR && return 0
  fi
  if [ ! -z $SENSOR_ZIP_FILE ] ; then
    [ ! -e $SENSOR_ZIP_FILE ] && echo "$SENSOR_ZIP_FILE does not exist" && log "Error: $SENSOR_ZIP_FILE does not exist" && cd $EXEC_DIR && rm -rf $TMP_DIR && return 1
    cp $SENSOR_ZIP_FILE $TMP_FILE
  fi
  [ ! -z $SAVE_ZIP_FILE ] && cp $TMP_FILE $SAVE_ZIP_FILE && cd $EXEC_DIR && rm -rf $TMP_DIR && return 0 
  unzip $TMP_FILE
  [ $? -ne 0 ] && log "Sensor pkg can not be extracted" && cd $EXEC_DIR && rm -rf $TMP_DIR && return 1

  # copy the rpm file
  inner_rpm=$(ls tet-sensor*.rpm| head -1 | awk '{print $1}')
  [ ! -z $FORCE_UPGRADE ] && cp $inner_rpm /usr/local/tet/conf_update.rpm && cd $EXEC_DIR && rm -rf $TMP_DIR && return 0
  cp $inner_rpm $RPM_FILE

  # Execute the rest from outside of temporary folder
  cd $EXEC_DIR

  # Verify that the rpm package is signed by Tetration
  log "Verifying Linux RPM package ..."
  LOCAL_RPMDB=$TMP_DIR
  rpm --initdb --dbpath $LOCAL_RPMDB
  rpm --dbpath $LOCAL_RPMDB --import $TMP_DIR/sensor-gpg.key
  gpg_ok=$(rpm -K $TMP_DIR/$RPM_FILE --dbpath $LOCAL_RPMDB)
  ret=$?
  if [ $ret -eq 0 ] ; then
    pgp_signed=$(echo $gpg_ok | grep -e "gpg\|pgp" -e "signatures OK")
    if [ "$pgp_signed" = "" ] ; then
      log "Error: RPM signature verification failed"
      rm -rf $TMP_DIR
      return 1
    else
      log "RPM package is PGP-signed"
    fi
  else
    log "Error: Cannot verify RPM package - $gpg_ok"
    rm -rf $TMP_DIR
    return 1
  fi

  log "Installing Linux Sensor ..."
  # make sure we are starting from clean state
  mkdir -p /usr/local/tet/chroot /usr/local/tet/conf /usr/local/tet/cert/
  rm -f /usr/local/tet/site.cfg
  [ -e $TMP_DIR/sensor.cfg ] && install -m 644 $TMP_DIR/sensor.cfg /usr/local/tet/conf/.sensor_config
  [ -e $TMP_DIR/enforcer.cfg ] && install -m 644 $TMP_DIR/enforcer.cfg /usr/local/tet/conf/enforcer.cfg
  install -m 644 $TMP_DIR/ta_sensor_ca.pem /usr/local/tet/cert/ca.cert
  # sensor rpm is supposed to check this file and start enforcer service
  sh -c "echo -n "$SENSOR_TYPE" > /usr/local/tet/sensor_type"
  # copy user.cfg file if the old file does not exist
  test -f /usr/local/tet/user.cfg
  [ $? -ne 0 ] && [ -e $TMP_DIR/tet.user.cfg ] && install -m 644 $TMP_DIR/tet.user.cfg /usr/local/tet/user.cfg

  RPM_INSTALL_OPTION=
  [ "$DISTRO" = "Ubuntu" ] && RPM_INSTALL_OPTION="--nodeps"
  ret=0
  rpm -Uvh $RPM_INSTALL_OPTION $TMP_DIR/$RPM_FILE
  if [ $? -ne 0 ] ; then
    log "Error: the command rpm -Uvh has failed, please check errors"
    ret=1
  else
    log "### Installation succeeded"
  fi

  # Clean up temporary files and folders
  log "Cleaning temporary files"
  rm -rf $TMP_DIR

  return $ret
}

function upgrade {
  check_sensor_exists && return 1
  if [ -z $SENSOR_VERSION ] ; then
    log "Upgrading to the latest version"
  else
    log "Upgrading to the provided version: $SENSOR_VERSION"
  fi
  # Download zip file and force upgrade
  if [ ! -z "$FORCE_UPGRADE" ] ; then
    perform_install
    [ $? -ne 0 ] && return 1
    # Set DONOT_DOWNLOAD
    [ ! -e /usr/local/tet/DONOT_DOWNLOAD ] && touch /usr/local/tet/DONOT_DOWNLOAD
    current_version=$(cat /usr/local/tet/conf/version)
    # Trigger check_conf_update
    PID=$(ps -ef | grep "tet-engine check_conf" | grep -v grep | awk {'print $2'})
    kill -USR1 $PID
    # Cleanup after upgrade
    count=0
    until [ $count -ge 6 ]
    do
      log "Checking upgrade status..."
      count=$[$count+1]
      sleep 15
      new_version=$(cat /usr/local/tet/conf/version)
      [ "$new_version" != "$current_version" ] && log "Upgrade succeeded" && rm -f /usr/local/tet/DONOT_DOWNLOAD && return 0
    done
    log "Upgrade timeout, cleanning up tmp files" 
    rm -f /usr/local/tet/DONOT_DOWNLOAD
    rm -f /usr/local/tet/conf_update.rpm
    return 1
  fi
  # Send sensor version update request
  [ ! -e $UUID_FILE ] && log "$UUID_FILE does not exist" && return 1
  perform_install
  [ $? -eq 0 ] && log "Upgrade triggered" && return 0
  return 1
}

for i in "$@"; do
case $i in
  --skip-pre-check)
  DO_PRECHECK=0
  shift
  ;;
  --no-install)
  NO_INSTALL=1
  shift
  ;;
  --logfile=*)
  LOG_FILE="${i#*=}"
  truncate -s 0 $LOG_FILE
  shift
  ;;
  --proxy=*)
  CL_HTTPS_PROXY="${i#*=}"
  PROXY_ARGS="-x $CL_HTTPS_PROXY"
  shift
  ;;
  --skip-ipv6-check)
  SKIP_IPV6=1
  shift
  ;;
  --sensor-version=*)
  SENSOR_VERSION="${i#*=}"
  shift
  ;;
  --file=*)
  SENSOR_ZIP_FILE=$(fullname "${i#*=}")
  shift
  ;;
  --save=*)
  SAVE_ZIP_FILE=$(fullname "${i#*=}")
  shift
  ;;
  --new)
  CLEANUP=1
  shift
  ;;
  --help)
  print_version
  echo
  print_usage
  exit 0
  shift
  ;;
  --version)
  print_version
  exit 0
  shift
  ;;
  --ls)
  LIST_VERSION="True"
  shift
  ;;
  --force-upgrade)
  FORCE_UPGRADE="True"
  shift
  ;;
  --upgrade=*)
  UUID_FILE="${i#*=}"
  [ -z $UUID_FILE ] && log "filename for --upgrade can't be empty" && exit 240
  UUID_FILE=$(fullname "$UUID_FILE")
  shift
  ;;
  *)
  echo "Invalid option: $@"
  print_usage
  exit 240
  ;;
esac
done

# Script needs to to be invoked as root
if [ "$UID" != 0 ] ; then
  log "Script needs to be invoked as root"
  exit 255
fi

# --ls to list all available sensor versions. will not download or install anything
if [ $LIST_VERSION = "True" ] ; then
  perform_install
  if [ $? -ne 0 ] ; then
    log "Failed to list all available sensor versions"
    exit 1
  fi
  exit 0
fi

# Download and save zip file
if [ ! -z $SAVE_ZIP_FILE ] ; then
  perform_install
  if [ $? -ne 0 ] ; then
    log "Failed to save zip file"
    exit 238
  fi
  exit 0
fi

# Make sure pre-check has passed
if [ $DO_PRECHECK -eq 1 ] ; then
  pre_check
  PRECHECK_RET=$?
  if [ $PRECHECK_RET -ne 0 ] ; then
    log "Pre-check has failed with code $PRECHECK_RET, please fix the errors"
    exit $PRECHECK_RET
  fi
fi

# Force upgrade to provided version
if [ ! -z $FORCE_UPGRADE ] || [ ! -z $UUID_FILE ] ; then
  upgrade
  [ $? -ne 0 ] && log "Sensor upgrade failed" && exit 237
  exit 0
fi

# Only proceed with installation if instructed
if [ $NO_INSTALL -eq 0 ] ; then
  NO_INSTALL=2
  perform_install
  if [ $? -ne 0 ] ; then
    log "Installation has failed, please check and fix the errors"
    exit 239
  fi
fi

log ""
log "### All tasks are done ###"
exit 0
