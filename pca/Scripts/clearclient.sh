# here we may back these files first 
echo "clear client env"
ScirptPath=$(cd `dirname $0`; pwd)
echo $ScirptPath
source $ScirptPath/header.sh
cd $CLIENTPATH
CUR=`pwd`
echo "CLIENTPATH is " $CLIENTPATH
echo "CUR is" $CUR
if [ $CUR = $CLIENTPATH ]
then
    echo "start to clean"
    rm -rf certs crl  openssl.cnf requests
else
    echo "oh, my god!"
fi
#
echo "clean all"